# shared/L3Router_allow_all.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, arp
from ryu.ofproto import ether

import ipaddress


class L3RouterAllowAll(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3RouterAllowAll, self).__init__(*args, **kwargs)

        # ARP table: IP -> (MAC,port)
        self.arp_table = {}

        self.mac_to_port = {}

        # router interfaces (the topology)
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

    #Make the routing fast, not all packets go to the controller (only the first ones go there, next ones find the FLOW already set).
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id :
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

    '''
    With no matching flow => pkt is sent to the controller as "PacketIN"
    The controller after receiving the pkt, checks IPs , builds actions
    And installs a new flow on the switch
    '''
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Table-miss flow installed")

    #Given an IP address, it determines which subnet it belongs to
    def _get_out_iface(self, dst_ip):
        ip = ipaddress.ip_address(dst_ip)
        for port_no, iface in self.interfaces.items():
            if ip in iface["net"]:
                return port_no, iface
        return None, None

    '''
    1- Builds the arp table (ip -> (mac / port)
    2- Gives the mac address # gateway IP (of router) {so host can reach the router}
    3- Floods the arp within the same LAN {so host can reach another host in the same LAN => router acts as a pure switch here}
    ==> enables reaching hosts within and in diff arps
    '''
    def _handle_arp(self, msg, in_port, pkt, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn sender IP -> MAC -> port
        self.arp_table[src_ip] = (src_mac, in_port)
        self.logger.info("ARP learn: %s is at %s (port %d)",
                         src_ip, src_mac, in_port)

        # If this is an ARP request for one of the gateway IPs, reply
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if dst_ip matches interface IP on this port
            for port_no, iface in self.interfaces.items():
                if iface["ip"].compressed == dst_ip and port_no == in_port:
                    self.logger.info("ARP request for gateway %s on port %d",
                                     dst_ip, in_port)
                    # Build ARP reply
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

            #L2 routing
            self.logger.info("ARP not for router (L2), flooding")
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # ARP reply will be learned by arp_table above; nothing else required
            self.logger.info("Received ARP reply %s is at %s", src_ip, src_mac)

    # handles LLDP / ARP / non IPv4 / IPv4 pkts
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        # Handle ARP separately
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(msg, in_port, pkt, datapath)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            # Non-IP traffic: simple L2 learning switch behavior
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

        # ----------------- L3 ROUTING PATH -----------------
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        self.logger.info("IPv4 packet in: %s -> %s (in_port=%d)",
                         src_ip, dst_ip, in_port)

        # Decide outgoing interface based on destination network
        out_port, out_iface = self._get_out_iface(dst_ip)
        if out_port is None:
            self.logger.info("No route to %s, dropping", dst_ip)
            return

        # Don't send out the same port it came in when routing
        if out_port == in_port:
            # Same subnet case: we could do L2-only switching here.
            # For simplicity, let it behave as learning switch:
            dst_mac, dst_port = self.arp_table.get(dst_ip, (None, None))
            if dst_mac and dst_port:
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(in_port=in_port,
                                        eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=src_ip,
                                        ipv4_dst=dst_ip)
                self.add_flow(datapath, 1, match, actions,
                              buffer_id=msg.buffer_id)
                return
            else:
                # Flood to find the host
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=msg.data)
                datapath.send_msg(out)
                return

        # Cross-subnet routing: need destination MAC from ARP table
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            # We don't know the MAC yet: send ARP request from router and drop this packet.
            self.logger.info("No ARP entry for %s, sending ARP request", dst_ip)

            # Build an ARP request from router interface IP/MAC
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

            # Drop current packet; next one should succeed once ARP reply arrives
            return

        dst_mac, dst_host_port = dst_entry

        # Build actions: rewrite MACs and send out
        actions = [
            parser.OFPActionSetField(eth_src=out_iface["mac"]),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(dst_host_port)
        ]

        # Install flow so that subsequent packets are forwarded in datapath only
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        self.add_flow(datapath, 10, match, actions,buffer_id=msg.buffer_id)

        # If the switch didn't buffer, send the packet out ourselves
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
