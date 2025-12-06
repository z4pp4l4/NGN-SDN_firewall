
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, arp, tcp, udp, icmp
from ryu.lib.packet import ipv4, arp, tcp, udp, icmp
from ryu.ofproto import ether

import ipaddress
from collections import defaultdict, deque
import time
import socket
import json



HOST_IP = "172.17.0.1"
PORT = 5001


def connect_to_gui(max_retries=3, retry_delay=1):
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
############################################

def connect_to_gui():
    sock = socket.socket()

    while True:
        try:
            sock.connect((HOST_IP, PORT))
            print("[FIREWALL] Connected to GUI")
            return sock
        except Exception as e:
            print("[FIREWALL] GUI not ready, retrying...")
            time.sleep(1)

HOST_IP = "172.17.0.1"
PORT = 5001


def connect_to_gui(max_retries=3, retry_delay=1):
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
############################################

class SDNFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.name = "SDNFirewall"
        self.listener_started_firewall = False
########################
        self.blocked_ips = {}
        self.blacklist=set()

        # GUI connection so that I can receive the list of blocked ip addresses
        self.gui_sock = connect_to_gui()
############################
        # ARP table: IP -> (MAC, port)
        self.arp_table = {}
        self.mac_to_port = {}

        # Router interfaces - FIXED: Use actual OVS port numbers
        # Router interfaces - FIXED: Use actual OVS port numbers
        self.interfaces = {
            1: {  # eth1 = port 1
                "ip": ipaddress.ip_address("192.168.10.4"),
                "mac": "0a:b3:e7:ec:f4:3f",
                "mac": "0a:b3:e7:ec:f4:3f",
                "net": ipaddress.ip_network("192.168.10.0/29")
            },
            2: {  # eth2 = port 2
                "ip": ipaddress.ip_address("192.168.20.8"),
                "mac": "52:98:79:8f:df:e0",
                "mac": "52:98:79:8f:df:e0",
                "net": ipaddress.ip_network("192.168.20.0/28")
            }
        }
        self.dos_block_duration=10
        self.dos_block_duration=10
        # DoS detection: track packet rates per (src_ip, dst_ip, dst_port)
        self.packet_history = defaultdict(deque)
        self.dos_threshold = 10  # packets per window
        self.dos_window = 3  # seconds

        # Port scan detection
        self.port_scan_tracking = defaultdict(lambda: {"ports": set(), "first_time": time.time()})
        self.port_scan_threshold = 10
        self.port_scan_window = 30

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add flow with optional timeout"""
        # Port scan detection
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
    
    def notify_gui_block(self, ip, duration, reason):
        print("Notifying GUI about blocked IP:", ip, duration, reason)
        if not self.gui_sock:
            return   # GUI not connected, ignore
        """Send block event to GUI."""
        event = {
            "type": "block",
            "ip": ip,
            "duration": duration,
            "reason": reason
        }
        try:
            self.gui_sock.sendall((json.dumps(event) + "\n").encode())
        except:
            self.logger.error("Failed to send block event to GUI.")

    def block_ip(self, datapath, src_ip, duration=None, reason="manual"):
        if duration is None:
            duration = self.dos_block_duration

        self.blocked_ips[src_ip] = time.time() + duration
        self.add_drop_flow(datapath, src_ip, duration)
        self.notify_gui_block(src_ip, duration, reason)

        self.logger.warning("BLOCKED IP %s for %ds (%s)", src_ip, duration, reason)
       
    def is_ip_blocked(self, src_ip):
        """Check if IP is currently blocked; unblock automatically after timeout."""
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

###################gio#########################
    def add_to_blacklist(self, src_ip):
        """Permanently blacklist an IP."""
        self.blacklist.add(src_ip)
        self.logger.warning("BLACKLISTED IP: %s (permanent)", src_ip)
        self.notify_gui_block(src_ip, duration=-1, reason="blacklist")

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
###################################################
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
        """Detect port scans"""

    def detect_port_scan(self, datapath, src_ip, dst_port):
        """Detect port scans"""
        flow_key = src_ip
        current_time = time.time()
        tracking = self.port_scan_tracking[flow_key]

        # Reset if outside window
        if (current_time - tracking["first_time"]) > self.port_scan_window:
            tracking["ports"].clear()
            tracking["first_time"] = current_time

        tracking["ports"].add(dst_port)

        if len(tracking["ports"]) >= self.port_scan_threshold:
            self.logger.warning("PORT SCAN DETECTED: %s scanning %d unique ports",
                              src_ip, len(tracking["ports"]))
            self.block_ip(datapath, src_ip, duration=180,reason="port_scan")
            self.add_to_blacklist(src_ip)     # <-- MUST BE RESTORED
            return True
        return False
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 0) Table-miss: send unknown stuff to controller (keep)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Table-miss flow installed")

        # 1) HIGH-PRIORITY INSPECTION RULE ON EXTERNAL PORT
        # external is port 2 in your `self.interfaces` and in flows (in_port=eth2)
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
        """Handle ARP packets"""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn ARP mapping
        # Learn ARP mapping
        self.arp_table[src_ip] = (src_mac, in_port)
        self.logger.info("ARP learn: %s is at %s (port %d)", src_ip, src_mac, in_port)
        self.logger.info("ARP learn: %s is at %s (port %d)", src_ip, src_mac, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if request is for our router interface
            # Check if request is for our router interface
            for port_no, iface in self.interfaces.items():
                if iface["ip"].compressed == dst_ip and port_no == in_port:
                    # Reply with our MAC
                    self.logger.info("ARP request for gateway %s, replying", dst_ip)
                    
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
        # Handle IPv4
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            # Non-IP traffic - basic L2 switching
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            
            # Non-IP traffic - basic L2 switching
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            
            src = eth.src
            dst = eth.dst
            self.mac_to_port[dpid][src] = in_port

            out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
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
        # === L3 ROUTING + SECURITY ===
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # Check if source IP is blocked
        # Check if source IP is blocked
        if self.is_ip_blocked(src_ip):
            self.logger.warning("DROPPING packet from blocked IP: %s", src_ip)
            return

        # Extract port numbers
        # Extract port numbers
        dst_port = None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            dst_port = udp_pkt.dst_port

        
        if dst_port:
            if self.detect_dos(datapath, src_ip, dst_ip, dst_port):
                return
            if self.detect_port_scan(datapath, src_ip, dst_port):
                return

        self.logger.info("IPv4: %s -> %s (port %d)", src_ip, dst_ip, in_port)
        self.logger.info("IPv4: %s -> %s (port %d)", src_ip, dst_ip, in_port)

        # Determine output interface
        # Determine output interface
        out_port, out_iface = self._get_out_iface(dst_ip)
        if out_port is None:
            self.logger.info("No route to %s, dropping", dst_ip)
            return

        # Same subnet (no routing needed)
        # Same subnet (no routing needed)
        if out_port == in_port:
            dst_entry = self.arp_table.get(dst_ip)
            if dst_entry:
                dst_mac, dst_host_port = dst_entry
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
                self.add_flow(datapath, 10, match, actions)
            else:
                # Flood on same subnet
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
        # Different subnet (routing needed)
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("No ARP entry for %s, sending ARP request", dst_ip)
            self._send_arp_request(datapath, dst_ip, out_port, out_iface)
            self._send_arp_request(datapath, dst_ip, out_port, out_iface)
            return

        dst_mac, dst_host_port = dst_entry

        # Install forwarding flow with MAC rewrite
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
