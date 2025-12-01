from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from ryu.lib.packet import ether_types
import time

class L3Firewall(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    # Detection thresholds
    PORTSCAN_WINDOW = 10
    PORTSCAN_THRESHOLD = 10
    DOS_WINDOW = 5
    DOS_THRESHOLD = 100
    BLOCK_DURATION = 60

    def __init__(self, *args, **kwargs):
        super(L3Firewall, self).__init__(*args, **kwargs)

        # L2 forwarding state
        self.mac_to_port = {}

        # Security state
        self.black_list = {}
        self.portscan_state = {}
        self.dos_state = {}

        # Static L3/L4 rules
        self.static_rules = [
            ("tcp_dst", 2020),
        ]

        self.packets_counter = 0
        self.packets_blocked = 0

    # ---------- FLOW INSTALLATION ----------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    # ---------- TABLE MISS ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)
        self.logger.info("L3 Firewall active")

    # ---------- PACKET HANDLER ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match['in_port']
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        # L2 learning
        self.mac_to_port[dpid][src] = in_port

        # ---------- ALLOW ARP ----------
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.forward_l2(datapath, in_port, dst, msg)
            return

        # ---------- L3 FILTERING ----------
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            now = time.time()

            # Check blacklist
            if src_ip in self.black_list and self.black_list[src_ip] > now:
                self.packets_blocked += 1
                self.logger.info("DROP (blacklisted) %s", src_ip)
                return

            # Check static rules
            if self.static_rules_control(tcp_pkt, udp_pkt, ipv4_pkt):
                match = self.build_match(parser, ipv4_pkt, tcp_pkt, udp_pkt)
                self.add_drop_rule(datapath, match, "static")
                self.black_list[src_ip] = now + self.BLOCK_DURATION
                return

            # Update detection state
            self.update_portscan(src_ip, tcp_pkt, udp_pkt, now)
            self.update_dos(src_ip, now)

            # Portscan detection
            if self.is_portscan(src_ip, now):
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                self.add_drop_rule(datapath, match, "portscan")
                self.black_list[src_ip] = now + self.BLOCK_DURATION
                return

            # DoS detection
            if self.is_dos(src_ip, now):
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                self.add_drop_rule(datapath, match, "DoS")
                self.black_list[src_ip] = now + self.BLOCK_DURATION
                return

        # ---------- L2 FORWARDING ----------
        self.forward_l2(datapath, in_port, dst, msg)

    # ---------- L2 FORWARD ----------
    def forward_l2(self, datapath, in_port, dst, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)

    # ---------- HELPERS ----------
    def static_rules_control(self, tcp_pkt, udp_pkt, ipv4_pkt):
        for field, value in self.static_rules:
            if field == "tcp_dst" and tcp_pkt:
                if tcp_pkt.dst_port == value:
                    return True
        return False

    def build_match(self, parser, ipv4_pkt, tcp_pkt, udp_pkt):
        kw = {"eth_type": 0x0800, "ipv4_src": ipv4_pkt.src}
        if tcp_pkt:
            kw["ip_proto"] = 6
            kw["tcp_dst"] = tcp_pkt.dst_port
        return parser.OFPMatch(**kw)

    def add_drop_rule(self, datapath, match, reason):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100,
            match=match, instructions=[]
        )
        datapath.send_msg(mod)
        self.logger.warning("DROP rule installed: %s", reason)

    # Detection logic
    def update_portscan(self, src_ip, tcp_pkt, udp_pkt, now):
        if not tcp_pkt and not udp_pkt:
            return
        port = tcp_pkt.dst_port if tcp_pkt else udp_pkt.dst_port
        self.portscan_state.setdefault(src_ip, []).append((now, port))

    def is_portscan(self, src_ip, now):
        entries = self.portscan_state.get(src_ip, [])
        recent = [p for (t, p) in entries if now - t <= self.PORTSCAN_WINDOW]
        return len(set(recent)) >= self.PORTSCAN_THRESHOLD

    def update_dos(self, src_ip, now):
        self.dos_state.setdefault(src_ip, []).append(now)

    def is_dos(self, src_ip, now):
        timestamps = self.dos_state.get(src_ip, [])
        recent = [t for t in timestamps if now - t <= self.DOS_WINDOW]
        return len(recent) >= self.DOS_THRESHOLD
