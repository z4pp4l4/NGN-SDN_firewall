
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, arp, tcp, udp, icmp
from ryu.ofproto import ether

import ipaddress
from collections import defaultdict, deque
import time
import socket
import json

from ryu.lib import hub

HOST_IP = "172.17.0.1"
PORT = 5001

def connect_to_gui(max_retries=100, retry_delay=1):
    sock = socket.socket()

    for attempt in range(1, max_retries + 1):
        try:
            sock.connect((HOST_IP, PORT))
            print(f"[FIREWALL] Connected to GUI (attempt {attempt})")
            return sock
        except Exception as e:
            print(f"[FIREWALL] GUI not ready (attempt {attempt}/{max_retries})...")
            time.sleep(retry_delay)

    print("[FIREWALL] GUI not reachable, continuing WITHOUT GUI connection.")
    return None

def connect_to_gui_channel(port, desc):
    sock = socket.socket()
    while True:
        try:
            sock.connect((HOST_IP, port))
            print(f"[FIREWALL] Connected to GUI {desc} channel on {port}")
            return sock
        except:
            print(f"[FIREWALL] GUI {desc} not ready, retrying...")
            time.sleep(1)


class SDNFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.name = "SDNFirewall"
        self.datapath = None
        self.listener_started_firewall = False
        self.blocked_ips = {}
        self.blacklist=set()

        
        self.static_block_ips = set()
        # each rule: {"protocol": "TCP"/"UDP", "port": 2020, "direction": "any"|"inbound"|"outbound"}
        self.static_port_rules = []

        # GUI connection so that can receive the list of blocked ip addresses
        self.gui_sock = connect_to_gui()
        # Command channel for receiving commands from GUI
        self.gui_cmd_socket = connect_to_gui_channel(6001, "command")
        hub.spawn(self.listen_to_gui_commands)

    
        # ARP table: IP -> (MAC, port)
        self.arp_table = {}
        self.mac_to_port = {}

        # Router interfaces - FIXED: Use actual OVS port numbers
        self.interfaces = {
            1: {  # eth1 = port 1
                "ip": ipaddress.ip_address("192.168.10.4"),
                "mac": "0a:b3:e7:ec:f4:3f",
                "net": ipaddress.ip_network("192.168.10.0/29")
            },
            2: {  # eth2 = port 2
                "ip": ipaddress.ip_address("192.168.20.8"),
                "mac": "52:98:79:8f:df:e0",
                "net": ipaddress.ip_network("192.168.20.0/28")
            }
        }
        self.dos_block_duration=20
        self.packet_history = defaultdict(deque)
        self.dos_threshold = 10  # packets per window
        self.dos_window = 3  # seconds

        self.port_scan_tracking = defaultdict(lambda: {"ports": set(), "first_time": time.time()})
        self.port_scan_threshold = 10
        self.port_scan_window = 30


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add flow with optional timeout"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        self.logger.info("Installing flow: priority=%d, match=%s", priority, match)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, src_ip, duration=120):
        """Install a drop flow for blocked IP"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Drop all traffic FROM this IP
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )
        
        # Empty actions = drop
        self.add_flow(datapath, 1000, match, [], hard_timeout=duration)
        self.logger.warning("DROP FLOW installed for %s (duration=%ds)", src_ip, duration)
    
    def remove_drop_flow(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        self.logger.warning("DROP FLOW REMOVED for %s", src_ip)

    def remove_port_drop_flow(self, datapath, protocol, port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match_kwargs = {
            "eth_type": ether_types.ETH_TYPE_IP,
        }

        if protocol.upper() == "TCP":
            match_kwargs["ip_proto"] = 6
            match_kwargs["tcp_dst"] = port
        elif protocol.upper() == "UDP":
            match_kwargs["ip_proto"] = 17
            match_kwargs["udp_dst"] = port

        match = parser.OFPMatch(**match_kwargs)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )

        datapath.send_msg(mod)
        self.logger.warning("PORT DROP FLOW REMOVED for %s %d", protocol, port)


    def notify_gui_block(self, ip, type, duration, reason):
        print("Notifying GUI about blocked IP:", ip, duration, reason)
        if not self.gui_sock:
            return   # GUI not connected, ignore
        #Sending event to GUI 
        if type=="block":
            event = {
                "type": type,
                "ip": ip,
                "duration": duration,
                "reason": reason
            }
        elif type=="unblock":
            event = {
                "type": type,
                "ip": ip,
                "reason": reason
            }
        
        try:
            print("notify socket:", self.gui_sock)
            self.gui_sock.sendall((json.dumps(event) + "\n").encode())
            print("Sent block event to GUI:", event)
        except:
            self.logger.error("Failed to send block event to GUI.")
            print("Failed to send block event to GUI.")

    def listen_to_gui_commands(self):
        buffer = ""
        while True:
            try:
                print("Listening for GUI commands...")
                data = self.gui_cmd_socket.recv(1024)
                if not data:
                    hub.sleep(1)
                    continue

                buffer += data.decode()

                while "\n" in buffer:
                    print("GUI socket: {}",self.gui_cmd_socket)
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        try:
                            cmd = json.loads(line)
                            print("[FIREWALL] Received GUI COMMAND:", cmd)
                            self.handle_gui_command(cmd)
                        except Exception as e:
                            print("[FIREWALL] Failed to parse GUI command:", e)

            except Exception as e:
                print("Error in GUI listener:", e)
                self.logger.error("GUI listener error: %s", e)
                hub.sleep(1)

    def handle_gui_command(self, cmd):
        """
        Handle JSON command from GUI.
                "block_ip",
                "unblock_ip",
                "static_block_ip",
                "static_unblock_ip",
                "block_port",
                "unblock_port",
        """
        cmd_type = cmd.get("type")
        ip = cmd.get("ip")
        duration = cmd.get("duration")
        dp = self.datapath

        if cmd_type == "block_ip" and dp and ip:
            print("Blocking IP from GUI command:", ip, duration)
            self.block_ip(dp, ip, duration=duration, reason="manual")
            # Notify GUI
            self.notify_gui_block("block",ip, duration, "manual")
            return
        
        if cmd_type == "unblock_ip" and ip:
            print("Unblocking IP from GUI command:", ip)
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
        
            if self.datapath:
                self.remove_drop_flow(self.datapath, ip)
            # Notify GUI (duration=0 means unblocked)
            self.notify_gui_block(ip,"block", 0, "unblocked")
            return

        if cmd_type == "static_block_ip" and dp and ip:
            print("Statically blocking IP from GUI command:", ip)
            self.add_static_ip_block(dp, ip)
            # Static block → duration = -1
            self.notify_gui_block(ip, "block", -1, "static_block")
            return

        if cmd_type == "static_unblock_ip" and ip:
            print("Removing static block for IP from GUI command:", ip)
            self.remove_static_ip_block(ip)
            if self.datapath:
                self.remove_drop_flow(self.datapath, ip)
            # Notify GUI
            self.notify_gui_block(ip, "unblock", 0, "static_unblock")
            return

        if cmd_type == "block_port" and dp:
            print("Blocking port from GUI command:", cmd)
            proto = cmd.get("protocol", "TCP").upper()
            port = int(cmd.get("port", 0))
            direction = cmd.get("direction", "any")

            if port > 0:
                self.add_static_port_rule(dp, proto, port, direction)

                # Use a synthetic "IP" key so GUI can show popups
                fake_ip = f"PORT-{proto}-{port}-{direction}"
                self.notify_gui_block(fake_ip, "block", -1, "static_port")
            return

        if cmd_type == "unblock_port":
            print("Unblocking port from GUI command:", cmd)
            proto = cmd.get("protocol", "TCP").upper()
            port = int(cmd.get("port", 0))
            direction = cmd.get("direction", "any")

            if port > 0:
                self.remove_static_port_rule(proto, port, direction)
                fake_ip = f"PORT-{proto}-{port}-{direction}"
            return



    def block_ip(self, datapath, src_ip, duration=None, reason="manual"):
        if duration is None:
            duration = self.dos_block_duration

        self.blocked_ips[src_ip] = time.time() + duration
        self.add_drop_flow(datapath, src_ip, duration)
        self.notify_gui_block(src_ip, "block", duration, reason)

        self.logger.warning("BLOCKED IP %s for %ds (%s)", src_ip, duration, reason)
       
    def is_ip_blocked(self, src_ip):
        """Check if IP is currently blocked; unblock automatically after timeout."""
        # Static IP block: never auto-expires
        if src_ip in self.static_block_ips:
            return True
        
        if src_ip in self.blacklist:
            return True
        # Not in block list → not blocked
        if src_ip not in self.blocked_ips:
            return False

        expiry = self.blocked_ips[src_ip]
        current_time = time.time()

        # Still blocked
        if current_time < expiry:
            return True

        # Timeout expired → unblock
        self.logger.warning("UNBLOCKING IP: %s (timeout expired)", src_ip)
        del self.blocked_ips[src_ip]
        return False

    # ----- STATIC IP RULES ------------------------------------------------
    def add_static_ip_block(self, datapath, ip):
        """Add a static IP block (never expires until manually removed)."""
        if ip in self.static_block_ips:
            return
        self.static_block_ips.add(ip)
        # static rule: use 0 hard_timeout => permanent
        self.add_drop_flow(datapath, ip, duration=0)
        self.notify_gui_block(ip, "block", duration=-1, reason="static")
        self.logger.warning("STATIC IP BLOCK added for %s", ip)

    def remove_static_ip_block(self, ip):
        """Remove a static IP block (note: flow removal not handled)."""
        if ip in self.static_block_ips:
            self.static_block_ips.remove(ip)
            self.logger.info("STATIC IP BLOCK removed for %s", ip)
            # possibly flow-mod delete here 
            
            return True
        return False
    # ----- STATIC PORT RULES ----------------------------------------------

    def add_static_port_rule(self, datapath, protocol, port, direction="any"):
        """Add static rule to block traffic by port (e.g. TCP dst_port 2020)."""
        rule = {
            "protocol": protocol.upper(),
            "port": port,
            "direction": direction  # "any" | "inbound" | "outbound"
        }
        if rule in self.static_port_rules:
            return

        self.static_port_rules.append(rule)
        self.logger.warning("STATIC PORT RULE added: %s", rule)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match_kwargs = {
            "eth_type": ether_types.ETH_TYPE_IP,
        }
        if protocol.upper() == "TCP":
            match_kwargs["ip_proto"] = 6
            match_kwargs["tcp_dst"] = port
        elif protocol.upper() == "UDP":
            match_kwargs["ip_proto"] = 17
            match_kwargs["udp_dst"] = port

        # Direction can be approximated by in_port: internal vs external
        match = parser.OFPMatch(**match_kwargs)
        self.add_flow(datapath, 900, match, [], hard_timeout=0)  # permanent drop
        self.logger.warning("STATIC DROP FLOW installed for %s %s", protocol, port)

    def remove_static_port_rule(self, protocol, port, direction="any"):
        """Remove a static port rule from local list (flows will persist until restart)."""
        rule = {
            "protocol": protocol.upper(),
            "port": port,
            "direction": direction
        }
        if rule in self.static_port_rules:
            self.static_port_rules.remove(rule)
            self.logger.info("STATIC PORT RULE removed: %s", rule)
            if self.datapath:
                self.remove_port_drop_flow(self.datapath, protocol, port)
            # Explicit flow removal could be implemented here if needed
            self.notify_gui_block(
                ip=f"PORT-{protocol.upper()}-{port}",
                type = "unblock",
                duration=0,
                reason="port_unblocked"
            )

    def matches_static_port_rule(self, in_port, src_ip, dst_ip, tcp_pkt, udp_pkt):
        """Check packet against static port rules (software check)."""
        for rule in self.static_port_rules:
            proto = rule["protocol"]
            port = rule["port"]
            direction = rule["direction"]

            pkt_port = None
            if proto == "TCP" and tcp_pkt:
                pkt_port = tcp_pkt.dst_port
            elif proto == "UDP" and udp_pkt:
                pkt_port = udp_pkt.dst_port

            if pkt_port is None or pkt_port != port:
                continue

            # Direction : 1 = internal, 2 = external
            if direction == "any":
                return True
            if direction == "outbound" and in_port == 1:
                return True
            if direction == "inbound" and in_port == 2:
                return True

        return False

#-------------------GUI retrieval of blacklist-----------------------
    def add_to_blacklist(self, src_ip):
        """Permanently blacklist an IP."""
        self.blacklist.add(src_ip)
        self.logger.warning("BLACKLISTED IP: %s (permanent)", src_ip)
        self.notify_gui_block(src_ip, "block", duration=-1, reason="blacklist")

    def remove_from_blacklist(self, src_ip):
        """Remove IP from permanent blacklist."""
        if src_ip in self.blacklist:
            self.blacklist.discard(src_ip)
            self.logger.info("REMOVED FROM BLACKLIST: %s", src_ip)
            return True
        return False

    def get_blacklist(self):
        """Get current blacklist (helper, e.g. for REST)."""
        return list(self.blacklist)

#-------------------GUI retrieval of blacklist-----------------------


    def detect_dos(self, datapath, src_ip, dst_ip, dst_port):
        """Detect DoS attacks based on packet rate over a sliding window."""
        flow_key = src_ip
        current_time = time.time()
        history = self.packet_history[flow_key]
        # Remove timestamps older than the window
        while history and (current_time - history[0]) > self.dos_window:
            history.popleft()
        # Add new timestamp
        history.append(current_time)

        # DoS condition:
        # 1) more than X packets
        # 2) all within dos_window seconds
        if len(history) > self.dos_threshold:
            time_window = history[-1] - history[0]   # duration between oldest and newest packet

            if time_window <= self.dos_window:
                self.logger.warning(
                    "DoS DETECTED from %s: %d packets in %.2f seconds",
                    src_ip, len(history), time_window
                )
                self.block_ip(datapath, src_ip,self.dos_block_duration,"dos")
                return True

        return False

    def detect_port_scan(self, datapath, src_ip, dst_port):
        now = time.time()
        tracking = self.port_scan_tracking[src_ip]
        # Rolling window update
        if now - tracking["first_time"] > self.port_scan_window:
            tracking["ports"].clear()
            tracking["first_time"] = now
        # Add port
        tracking["ports"].add(dst_port)
        # Detection threshold
        if len(tracking["ports"]) >= self.port_scan_threshold:
            self.logger.warning(f"PORT SCAN DETECTED from {src_ip}: {len(tracking['ports'])} unique ports")
            # Notify GUI immediately
            #self.notify_gui_block(src_ip, "block", duration=10, reason="port_scan_detected")
            # Temporary block
            self.block_ip(datapath, src_ip, duration=20, reason="port_scan")
            return True

        return False


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 0) Table-miss: send unknown stuff to controller (keep)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Table-miss flow installed")

        # 1) HIGH-PRIORITY INSPECTION RULE ON EXTERNAL PORT
        EXTERNAL_PORT = 2

        match = parser.OFPMatch(
            in_port=EXTERNAL_PORT,
            eth_type=ether_types.ETH_TYPE_IP
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # priority > 10 so it beats routing flows
        self.add_flow(datapath, 50, match, actions)
        self.logger.info("Inspection rule installed on external port %d", EXTERNAL_PORT)


    def _get_out_iface(self, dst_ip):
        """Determine outgoing interface for destination IP"""
        ip = ipaddress.ip_address(dst_ip)
        for port_no, iface in self.interfaces.items():
            if ip in iface["net"]:
                return port_no, iface
        return None, None


    def _send_arp_request(self, datapath, dst_ip, out_port, out_iface):
        """Send ARP request for unknown IP"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        iface_mac = out_iface["mac"]
        iface_ip = out_iface["ip"].compressed

        ether_req = ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src=iface_mac,
            ethertype=ether.ETH_TYPE_ARP
        )
        arp_req = arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=iface_mac,
            src_ip=iface_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=dst_ip
        )
        p = packet.Packet()
        p.add_protocol(ether_req)
        p.add_protocol(arp_req)
        p.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data
        )
        datapath.send_msg(out)
        self.logger.info("Sent ARP request for %s on port %d", dst_ip, out_port)



    def _handle_arp(self, msg, in_port, pkt, datapath):
        """Handle ARP packets"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn ARP mapping
        self.arp_table[src_ip] = (src_mac, in_port)
        self.logger.info("ARP learn: %s is at %s (port %d)", src_ip, src_mac, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if request is for our router interface
            for port_no, iface in self.interfaces.items():
                if iface["ip"].compressed == dst_ip and port_no == in_port:
                    # Reply with our MAC
                    self.logger.info("ARP request for gateway %s, replying", dst_ip)
                    
                    ether_reply = ethernet.ethernet(
                        dst=src_mac,
                        src=iface["mac"],
                        ethertype=ether.ETH_TYPE_ARP
                    )
                    arp_reply = arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=iface["mac"],
                        src_ip=dst_ip,
                        dst_mac=src_mac,
                        dst_ip=src_ip
                    )
                    p = packet.Packet()
                    p.add_protocol(ether_reply)
                    p.add_protocol(arp_reply)
                    p.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER,
                        actions=actions,
                        data=p.data
                    )
                    datapath.send_msg(out)
                    return

            # Not for us, flood
            self.logger.info("ARP request not for router, flooding")
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("Received ARP reply: %s is at %s", src_ip, src_mac)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Handle ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(msg, in_port, pkt, datapath)
            return

        # Handle IPv4
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:      
            # Non-IP traffic - basic L2 switching
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            
            src = eth.src
            dst = eth.dst
            self.mac_to_port[dpid][src] = in_port
            out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
            
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)
            return

        # === L3 ROUTING + SECURITY ===
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # Check if source IP is blocked
        if self.is_ip_blocked(src_ip):
            self.logger.warning("DROPPING packet from blocked IP: %s", src_ip)
            return

        # Extract port numbers
        dst_port = None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            dst_port = udp_pkt.dst_port

        # STATIC PORT RULES (e.g. block TCP dst_port 2020)
        if self.matches_static_port_rule(in_port, src_ip, dst_ip, tcp_pkt, udp_pkt):
            self.logger.warning(
                "STATIC PORT RULE DROP: %s -> %s (port %s, in_port %d)",
                src_ip, dst_ip, dst_port, in_port
            )
            return
        
        if dst_port:
            if self.detect_dos(datapath, src_ip, dst_ip, dst_port):
                return
            if self.detect_port_scan(datapath, src_ip, dst_port):
                return

        self.logger.info("IPv4: %s -> %s (port %d)", src_ip, dst_ip, in_port)

        # Determine output interface
        out_port, out_iface = self._get_out_iface(dst_ip)
        if out_port is None:
            self.logger.info("No route to %s, dropping", dst_ip)
            return

        # Same subnet (no routing needed)
        if out_port == in_port:
            dst_entry = self.arp_table.get(dst_ip)
        
            if dst_entry:
                dst_mac, dst_host_port = dst_entry
                actions = [parser.OFPActionOutput(dst_host_port)]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_flow(datapath, 10, match, actions)
            else:
                # Flood on same subnet
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)
            return
        
        # Different subnet (routing needed)
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("No ARP entry for %s, sending ARP request", dst_ip)
            self._send_arp_request(datapath, dst_ip, out_port, out_iface)
            return

        dst_mac, dst_host_port = dst_entry

        # Install forwarding flow with MAC rewrite
        actions = [
            parser.OFPActionSetField(eth_src=out_iface["mac"]),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionDecNwTtl(),  # Decrement TTL
            parser.OFPActionOutput(dst_host_port)
        ]

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        
        self.add_flow(datapath, 10, match, actions, idle_timeout=300)

        # Send packet out
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
