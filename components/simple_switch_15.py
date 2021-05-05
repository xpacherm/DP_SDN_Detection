# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet, ipv4, ipv6, in_proto, tcp, udp, arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    
    PSH_FLAG_COUNT_TABLE = 0
    URG_FLAG_COUNT_TABLE = 1
    SWITCHING_TABLE = 10

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self.URG_FLAG_COUNT_TABLE, ofproto.OFPIT_GOTO_TABLE)]
        self.add_flow(datapath, 0, match, inst, self.PSH_FLAG_COUNT_TABLE)
        
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self.SWITCHING_TABLE, ofproto.OFPIT_GOTO_TABLE)]
        self.add_flow(datapath, 0, match, inst, self.URG_FLAG_COUNT_TABLE)
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, self.SWITCHING_TABLE)

    def add_flow(self, datapath, priority, match, instructions, table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, table_id=table, priority=priority, 
                                match=match, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_proto = pkt.get_protocol(ipv4.ipv4)
        ipv6_proto = pkt.get_protocol(ipv6.ipv6)
        arp_proto = pkt.get_protocol(arp.arp)
        tcp_proto = pkt.get_protocol(tcp.tcp)
        udp_proto = pkt.get_protocol(udp.udp)
        
        # drop IPv6 packets
        if ipv6_proto is not None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_proto is not None:
                if ipv4_proto.proto is in_proto.IPPROTO_TCP: 
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=ipv4_proto.proto, 
                                            eth_dst=dst, 
                                            eth_src=src, 
                                            tcp_flags=(0x0008, 0x0008), 
                                            tcp_src=tcp_proto.src_port, 
                                            tcp_dst=tcp_proto.dst_port)
                    inst = [parser.OFPInstructionGotoTable(self.URG_FLAG_COUNT_TABLE, ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, 1, match, inst, self.PSH_FLAG_COUNT_TABLE)
                    
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=ipv4_proto.proto, 
                                            eth_dst=dst, 
                                            eth_src=src, 
                                            tcp_flags=(0x0020, 0x0020), 
                                            tcp_src=tcp_proto.src_port, 
                                            tcp_dst=tcp_proto.dst_port)
                    inst = [parser.OFPInstructionGotoTable(self.SWITCHING_TABLE, ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, 1, match, inst, self.URG_FLAG_COUNT_TABLE)
                    
                    match = parser.OFPMatch(in_port=in_port, 
                                            eth_type=ether_types.ETH_TYPE_IP, 
                                            ip_proto=ipv4_proto.proto, 
                                            eth_dst=dst, 
                                            eth_src=src, 
                                            tcp_src=tcp_proto.src_port, 
                                            tcp_dst=tcp_proto.dst_port)
                    priority = 5
                elif ipv4_proto.proto is in_proto.IPPROTO_UDP: 
                    match = parser.OFPMatch(in_port=in_port, 
                                            eth_type=ether_types.ETH_TYPE_IP, 
                                            ip_proto=ipv4_proto.proto, 
                                            eth_dst=dst, eth_src=src, 
                                            udp_src=udp_proto.src_port, 
                                            udp_dst=udp_proto.dst_port)
                    priority = 4
                else:    
                    match = parser.OFPMatch(in_port=in_port, 
                                            eth_type=ether_types.ETH_TYPE_IP, 
                                            ip_proto=ipv4_proto.proto, 
                                            eth_dst=dst, 
                                            eth_src=src)
                    priority = 3
            elif arp_proto is not None:
                match = parser.OFPMatch(in_port=in_port, 
                                        eth_type=ether_types.ETH_TYPE_ARP, 
                                        arp_spa=arp_proto.src_ip, 
                                        arp_tpa=arp_proto.dst_ip)
                priority = 2
            else:
                match = parser.OFPMatch(in_port=in_port, 
                                        eth_dst=dst, 
                                        eth_src=src)
                priority = 1   
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, priority, match, inst, self.SWITCHING_TABLE)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)
