from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
import time

class Firewall(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    #DEFINING THRESHOLD
    PORTSCAN_WINDOW = 10       # seconds
    PORTSCAN_THRESHOLD = 10    # distinct ports in window
    DOS_WINDOW = 5             # seconds
    DOS_THRESHOLD = 100        # packets in window
    BLOCK_DURATION = 60        # seconds (timed rule)

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #priority levels for execution
        self.PRIORITY_DEFAULT = 0
        self.PRIORITY_DROP = 100
        self.PRIORITY_ALLOW = 50
        # STATIC RULES:
        # tuple format: (field, value)
        self.static_rules = [
            ("tcp_dst", 2020),         # block any TCP dst port 2020
            # ...
        ]
        self.black_list = {}      # black list : (src_ip -> unblock_timestamp)
        self.portscan_state = {}      # (src_ip -> list of (timestamp, dst_port))
        self.dos_state = {}           # (src_ip -> list of timestamps)
        #statistics
        self.packets_counter = 0
        self.packets_blocked = 0

    def _cleanup_tracking_lists(self, now): #for tracking lists i mean portscan_state and dos_state
        """Remove old entries from all state dictionaries to prevent memory leaks."""
        # Cleaning up portscan state
        for ip in list(self.portscan_state.keys()):
            entries = self.portscan_state[ip]
            self.portscan_state[ip] = [(t, p) for (t, p) in entries 
                                    if (now - t <= self.PORTSCAN_WINDOW)]
            if (not self.portscan_state[ip]):
                del self.portscan_state[ip]
        # Clean DoS state
        for ip in list(self.dos_state.keys()):
            timestamps = self.dos_state[ip]
            self.dos_state[ip] = [t for t in timestamps 
                                if (now - t <= self.DOS_WINDOW)]
            if (not self.dos_state[ip]):
                del self.dos_state[ip]
        
        # Prevent unbounded growth
        if (len(self.portscan_state) > 10000): #THIS SHOULD NOT HAPPEN
            self.logger.warning("Too many tracked IPs, clearing old portscan state")
            self.portscan_state.clear()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #Install default behavior: send everything to controller.
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry: send packets to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER)
            ]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch connected (dpid=%s) - firewall active", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        #Install a flow on the switch supporting timeouts.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                instructions=instruction
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                instructions=instruction
            )
        datapath.send_msg(mod)

    def add_drop_rule(self, datapath, match, reason="unknown", duration=None):
        #Install a drop rule for an amount of time.
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if duration is not None:
            hard_timeout = duration
        else:
            hard_timeout = self.BLOCK_DURATION
        self.logger.warning(f"Installing DROP rule ({reason}) with hard_timeout={hard_timeout}, match={match}")

        inst = []  # no actions -> drop
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,   # higher than default
            match=match,
            idle_timeout=0,
            hard_timeout=hard_timeout,
            instructions=inst
        )
        datapath.send_msg(mod)

    # PACKET HANDLER 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def input_packet_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            input_port = msg.match['in_port']
            dpid = datapath.id
            
            # Increment packet counter (for stats)
            self.packets_counter += 1
            
            # Extract packet
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if eth is None:
                return
            destination = eth.dst
            src = eth.src
        
            # L2 learning
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = input_port
            
            # Allow ARP traffic (we can decide to block it later if needed)
            if (eth.ethertype == 0x0806):  # ARP
                self.logger.debug(f"ARP packet: {src} -> {destination}")
                self.forwarding(datapath, input_port, destination, msg)
                return
            elif (eth.ethertype == 0x0800):  # IPv4
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                if (ipv4_pkt is None):
                    # Should not happen, but handle gracefully
                    self.logger.warning(f"IPv4 ethertype (0x0800) but failed to parse packet")
                    return  # Drop malformed packets instead of forwarding
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                
                src_ip = ipv4_pkt.src
                dst_ip = ipv4_pkt.dst
                now = time.time() # current timestamp
                
                # Clean up stale state every 2000 packets to prevent memory leaks
                if (self.packets_counter % 2000== 0):
                    self._cleanup_tracking_lists(now)
                    self.logger.debug(
                        f"Stats - Processed: {self.packets_counter}, "
                        f"Blocked: {self.packets_blocked}, "
                        f"Tracked IPs: {len(self.portscan_state)}"
                    )
                
                # Release from blacklist  IPs with expired timer
                self.release_blocked_ips(now)
                #maybe add a whitelist for "trusted IPs"
                #check if incoming pck is in the blacklist
                if (src_ip in self.black_list and self.black_list[src_ip] > now): #second condition should not happen btw
                    self.packets_blocked += 1
                    self.logger.debug(f"DROPPED (blacklisted): {src_ip} -> {dst_ip}")
                    return
                
                # Static rules check (we decide)
                if (self.static_rules_control(tcp_pkt=tcp_pkt, udp_pkt=udp_pkt, ipv4_pkt=ipv4_pkt)==True):
                    match = self._build_match(parser, ipv4_pkt, tcp_pkt, udp_pkt)
                    self.add_drop_rule(datapath, match, reason="static rule")
                    self.packets_blocked += 1
                    return
                
                self.update_portscan_state(src_ip, tcp_pkt, udp_pkt, now)
                self.update_DOS_state(src_ip, now)
                
                #portscan detection
                if (self.portscan_detection(src_ip, now)==True):
                    self.logger.warning(
                        f"PORT SCAN DETECTED from {src_ip} - "
                        f"{len(self.portscan_state.get(src_ip, []))} distinct ports scanned"
                    )
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                    #react installing drop rule in controller and putting the scr_ip in black list
                    self.add_drop_rule(datapath, match, reason="PORTSCAN", duration=self.BLOCK_DURATION)
                    self.black_list[src_ip] = now + self.BLOCK_DURATION
                    self.packets_blocked += 1
                    # ***************to check this memory saving thing***************
                    # Clear state for this IP to save memory
                    if (src_ip in self.portscan_state):
                        del self.portscan_state[src_ip]
                    return
                
                # DOS detection
                if (self.DOS_detection(src_ip, now)==True):
                    self.logger.warning(
                        f"DOS ATTACK DETECTED from {src_ip} - "
                        f"{len(self.dos_state.get(src_ip, []))} packets in {self.DOS_WINDOW}s window"
                    )
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                    #install drop rule in controller and putting the scr_ip in black list
                    self.add_drop_rule(datapath, match, reason="DOS", duration=self.BLOCK_DURATION)
                    self.black_list[src_ip] = now + self.BLOCK_DURATION
                    self.packets_blocked += 1
                    # ***************to check this memory saving thing***************
                    # Clear state for this IP to save memory
                    if (src_ip in self.dos_state):
                        del self.dos_state[src_ip]
                    return
                #in case packet is not considered manacing
                self.logger.debug(f"IPv4 packet allowed: {src_ip} -> {dst_ip}")
                self.forwarding(datapath, input_port, destination, msg)
            else:  # Unknown protocol
                self.logger.debug(f"Unknown ethertype: 0x{eth.ethertype:04x}, forwarding")
                self.forwarding(datapath, input_port, destination, msg)
                return
                
        except KeyError as e:
            self.logger.error(f"KeyError in packet handler: {e} - possibly missing field in match")
        except Exception as e:
            self.logger.error(f"Unexpected error processing packet: {e}", exc_info=True)

    def forwarding(self, datapath, input_port, dst, msg): #normal forwarding function for authorized packets
        ofproto = datapath.ofproto #contains OF protocol constants
        parser= datapath.ofproto_parser #used to create OF protocol messages
        dpid= datapath.id

        self.mac_to_port.setdefault(dpid, {})
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        #sending out he packet to switch
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            input_port=input_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)


    #THIS FUNCTION IS EXTENDABLE TO ADD MORE STATIC RULES
    def static_rules_control(self, tcp_pkt=None, udp_pkt=None, ipv4_pkt=None):
        """Return True if the packet hits any static rule."""
        for field, value in self.static_rules:
            # Example: ("tcp_dst", 2020)
            if field == "tcp_dst" and tcp_pkt is not None:
                if tcp_pkt.dst_port == value:
                    self.logger.info(f"Static rule matched: TCP dst port {value}")
                    self.logger.info(f"BLOCKING packet from {ipv4_pkt.src} to {ipv4_pkt.dst} TCP dst port {tcp_pkt.dst_port}")
                    return True
            # you can extend with ip_src, ip_dst, udp_dst, etc.
        return False

    #TO CLARIFY THIS: WHAT DO WE DO IF WE DROP A PACKET?
    def _build_match(self, parser, ipv4_pkt, tcp_pkt, udp_pkt):
        """Build a match object for dropping similar traffic as this packet."""
        kwargs = {
            "eth_type": 0x0800,
            "ipv4_src": ipv4_pkt.src,
            "ipv4_dst": ipv4_pkt.dst
        }
        if tcp_pkt is not None:
            kwargs["ip_proto"] = 6
            kwargs["tcp_dst"] = tcp_pkt.dst_port
        elif udp_pkt is not None:
            kwargs["ip_proto"] = 17
            kwargs["udp_dst"] = udp_pkt.dst_port
        return parser.OFPMatch(**kwargs) #prepares the OpenFlow match used to block a specific type of pckt.

    #PORTSCAN (to see how it behaves with tools such as nmap)
    def update_portscan_state(self, src_ip, tcp_pkt, udp_pkt, now):
        if (tcp_pkt is None and udp_pkt is None):
            return
        elif (tcp_pkt is not None):
            dst_port = tcp_pkt.dst_port
        else:
            dst_port = udp_pkt.dst_port

        ports = self.portscan_state.setdefault(src_ip, [])
        ports.append((now, dst_port))
        # Remove old entries
        # self.portscan_state[src_ip] = [
        #     (t, p) for (t, p) in ports if now - t <= self.PORTSCAN_WINDOW
        # ]
    def portscan_detection(self, src_ip, now): 
        """could also be implemented in another way: considering the time difference between first and last port scanned by the Ip
        and see if that time window is very small (to consider it a portscan). 
        Like if I see that in 5 seconds an IP scanned 50 ports, it's probably a portscan """
        #for now stick with the distinct ports threshold
        entries = self.portscan_state.get(src_ip, [])
        distinct_ports = {ports for (t, ports) in entries}
        if len(distinct_ports) >= self.PORTSCAN_THRESHOLD:
            return True
        return False

    #DOS
    def update_DOS_state(self, src_ip, now):
        # Initialize list for new IPs
        if src_ip not in self.dos_state:
            self.dos_state[src_ip] = []
        # Record this packet's arrival time
        self.dos_state[src_ip].append(now)
        # Remove timestamps older than our detection window
        # window_start = now - self.DOS_WINDOW
        # self.dos_state[src_ip] = [
        #     t for t in self.dos_state[src_ip] 
        #     if t > window_start
        # ]
    def DOS_detection(self, src_ip, now):
        timestamps = self.dos_state.get(src_ip, [])
        recent = [t for t in timestamps if now - t <= self.DOS_WINDOW]
        if len(recent) >= self.DOS_THRESHOLD:
            return True
        return False


#relasing blocked IPs after timer expiration
    def release_blocked_ips(self, now):
        #Remove IPs Iin blacklist with timer expired
        # Loop through the blocked IP list
        for (ip, unblock_time) in list(self.black_list.items()):
            # If block duration is over
            if now >= unblock_time:
                self.logger.info(f"Block timer is expired for {ip}")
                # Remove from blocked list
                del self.black_list[ip]

