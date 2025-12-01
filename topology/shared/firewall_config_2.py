from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, arp, tcp, udp
from ryu.ofproto import ether

import ipaddress
from collections import defaultdict, deque
import time


class SDNFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)

        # ARP table: IP -> (MAC, port)
        self.arp_table = {}
        self.mac_to_port = {}

        # Router interfaces
        self.interfaces = {
            1: {
                "ip": ipaddress.ip_address("192.168.10.4"),
                "mac": "00:00:00:00:00:1b",
                "net": ipaddress.ip_network("192.168.10.0/29")
            },
            2: {
                "ip": ipaddress.ip_address("192.168.20.8"),
                "mac": "00:00:00:00:00:1c",
                "net": ipaddress.ip_network("192.168.20.0/28")
            }
        }

        # Firewall rules (currently unused but ready to be plugged in):
        # list of (src_ip, dst_ip, dst_port, protocol, action, expiry_time)
        self.firewall_rules = []

        # DoS detection: track packet rates per (src_ip, dst_ip, dst_port)
        self.packet_history = defaultdict(deque)
        self.dos_threshold = 100  # packets per 10 seconds
        self.dos_window = 10      # seconds
        self.dos_block_duration = 10  # seconds

        # Port scan detection: track unique destination ports per source IP
        self.port_scan_tracking = defaultdict(
            lambda: {"ports": set(), "first_time": time.time()}
        )
        self.port_scan_threshold = 10  # unique ports in scan_window
        self.port_scan_window = 30     # seconds
        self.port_scan_block_duration = 180  # seconds

        # Temporary blocks: IP -> expiry_time
        self.blocked_ips = {}

        # Blacklist: permanently blocked IPs
        self.blacklist = set()

    # ===================== FLOW MANAGEMENT =====================

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)

        self.logger.info("Sending FLOW_MOD to switch")
        datapath.send_msg(mod)

    # ===================== BLOCK / BLACKLIST =====================

    def block_ip(self, src_ip, duration=60):
        """Block an IP for specified duration (seconds)."""
        self.blocked_ips[src_ip] = time.time() + duration
        self.logger.warning("BLOCKED IP: %s for %d seconds", src_ip, duration)

    def is_ip_blocked(self, src_ip):
        """Check if IP is currently blocked (temporary or permanent)."""
        # Check permanent blacklist first
        if src_ip in self.blacklist:
            self.logger.info("IP %s is BLACKLISTED (permanent)", src_ip)
            return True

        # Check temporary blocks
        if src_ip in self.blocked_ips:
            expiry_time = self.blocked_ips[src_ip]
            current_time = time.time()

            if current_time < expiry_time:
                remaining = expiry_time - current_time
                self.logger.debug("IP %s is blocked, %.1f seconds remaining",
                                  src_ip, remaining)
                return True
            else:
                # Block has expired, remove it
                del self.blocked_ips[src_ip]
                self.logger.warning("UNBLOCKED IP: %s (timeout expired)", src_ip)
                return False

        return False

    def add_to_blacklist(self, src_ip):
        """Permanently blacklist an IP."""
        self.blacklist.add(src_ip)
        self.logger.warning("BLACKLISTED IP: %s (permanent)", src_ip)

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

    def get_blocked_ips(self):
        """Get current temporary blocks (not expired)."""
        current_time = time.time()
        active_blocks = {}
        for ip, expiry in list(self.blocked_ips.items()):
            if current_time < expiry:
                active_blocks[ip] = expiry - current_time
            else:
                del self.blocked_ips[ip]
        return active_blocks

    # ===================== DETECTION LOGIC =====================

    def detect_dos(self, src_ip, dst_ip, dst_port):
        """Detect DoS attacks based on packet rate."""
        flow_key = (src_ip, dst_ip, dst_port)
        current_time = time.time()

        # Clean old entries outside window
        while (self.packet_history[flow_key] and
               (current_time - self.packet_history[flow_key][0]) > self.dos_window):
            self.packet_history[flow_key].popleft()

        self.packet_history[flow_key].append(current_time)

        if len(self.packet_history[flow_key]) > self.dos_threshold:
            self.logger.warning(
                "DoS DETECTED: %s -> %s:%s (%d packets in %d seconds)",
                src_ip, dst_ip, dst_port,
                len(self.packet_history[flow_key]), self.dos_window
            )
            self.block_ip(src_ip, duration=self.dos_block_duration)
            return True
        return False

    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scans based on unique destination ports."""
        flow_key = src_ip
        current_time = time.time()
        tracking = self.port_scan_tracking[flow_key]

        # Reset if outside window
        if (current_time - tracking["first_time"]) > self.port_scan_window:
            tracking["ports"].clear()
            tracking["first_time"] = current_time

        tracking["ports"].add(dst_port)

        if len(tracking["ports"]) >= self.port_scan_threshold:
            self.logger.warning(
                "PORT SCAN DETECTED: %s scanning %d unique ports in %d seconds",
                src_ip, len(tracking["ports"]), self.port_scan_window
            )
            # Use both temporary block AND permanent blacklist so this helper is used
            self.block_ip(src_ip, duration=self.port_scan_block_duration)
            self.add_to_blacklist(src_ip)
            return True
        return False

    # ===================== ROUTING HELPERS =====================

    def _get_out_iface(self, dst_ip):
        """Determine outgoing interface for destination IP."""
        ip = ipaddress.ip_address(dst_ip)
        for port_no, iface in self.interfaces.items():
            if ip in iface["net"]:
                return port_no, iface
        return None, None

    # ===================== ARP HANDLING =====================

    def _handle_arp(self, msg, in_port, pkt, datapath):
        """Handle ARP requests and replies."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn sender
        self.arp_table[src_ip] = (src_mac, in_port)
        self.logger.info("ARP learn: %s is at %s (port %d)",
                         src_ip, src_mac, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if ARP is for one of our router interfaces
            for port_no, iface in self.interfaces.items():
                if iface["ip"].compressed == dst_ip and port_no == in_port:
                    self.logger.info("ARP request for gateway %s on port %d",
                                     dst_ip, in_port)
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

            # Not for us -> L2 flooding
            self.logger.info("ARP not for router (L2), flooding")
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("Received ARP reply %s is at %s", src_ip, src_mac)

    # ===================== RYU EVENT HANDLERS =====================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Table-miss flow installed")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Main packet-in handler: L2 learning, L3 routing, and security."""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Handle ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(msg, in_port, pkt, datapath)
            return

        # If not IPv4, do simple L2 switching
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            src = eth.src
            dst = eth.dst
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port,
                                        eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions,
                              buffer_id=msg.buffer_id)
                return

            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return

        # =============== L3 ROUTING + SECURITY PATH ===============
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # Check if source IP is blocked (temporary or permanent)
        if self.is_ip_blocked(src_ip):
            self.logger.warning("DROPPING packet from blocked IP: %s", src_ip)
            return

        # Extract transport-layer ports if present
        dst_port = None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            dst_port = udp_pkt.dst_port

        # DoS detection (if port is known)
        if dst_port is not None:
            if self.detect_dos(src_ip, dst_ip, dst_port):
                # Packet already handled by blocking
                return

        # Port scan detection
        if dst_port is not None:
            if self.detect_port_scan(src_ip, dst_port):
                # Packet already handled by blocking / blacklist
                return

        self.logger.info("IPv4 packet in: %s -> %s (in_port=%d)",
                         src_ip, dst_ip, in_port)

        # Determine outgoing interface
        out_port, out_iface = self._get_out_iface(dst_ip)
        if out_port is None:
            self.logger.info("No route to %s, dropping", dst_ip)
            return

        # Same subnet case
        if out_port == in_port:
            dst_mac, dst_host_port = self.arp_table.get(dst_ip, (None, None))
            if dst_mac and dst_host_port:
                actions = [parser.OFPActionOutput(dst_host_port)]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_flow(datapath, 1, match, actions,
                              buffer_id=msg.buffer_id)
                return
            else:
                # No ARP info, flood on this port
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=msg.data)
                datapath.send_msg(out)
                return

        # Different subnet: need ARP for next hop
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("No ARP entry for %s, sending ARP request", dst_ip)

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
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=ofp.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=p.data)
            datapath.send_msg(out)
            return

        # We know destination MAC from ARP table
        dst_mac, dst_host_port = dst_entry

        actions = [
            parser.OFPActionSetField(eth_src=out_iface["mac"]),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(dst_host_port)
        ]

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        self.add_flow(datapath, 10, match, actions, buffer_id=msg.buffer_id)

        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
