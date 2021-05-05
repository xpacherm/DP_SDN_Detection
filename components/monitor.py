# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from operator import attrgetter
from ryu.app import simple_switch_15
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime


class SimpleMonitor15(simple_switch_15.SimpleSwitch15):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor15, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.fields = {'time':'', 
                       'datapath':'', 
                       'in-port':'', 
                       'eth_src':'', 
                       'eth_dst':'',
                       'L4_proto':'', 
                       'L4_src':'', 
                       'L4_dst':'', 
                       'out-port':'', 
                       'total_packets':0, 
                       'total_bytes':0, 
                       'psh_flags':0, 
                       'urg_flags':0}

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):     
        while True:        
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowDescStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowDescStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        for stat in sorted([flow for flow in body if flow.priority > 3 and flow.table_id == 10], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            self.fields['time'] = datetime.utcnow().strftime('%s')
            self.fields['datapath'] = ev.msg.datapath.id
            self.fields['in-port'] = stat.match['in_port']
            self.fields['eth_src'] = stat.match['eth_src']
            self.fields['eth_dst'] = stat.match['eth_dst']
            self.fields['out-port'] = stat.instructions[0].actions[0].port
            self.fields['total_packets'] = stat.stats['packet_count']
            self.fields['total_bytes'] = stat.stats['byte_count']
            self.fields['psh_flags'] = 0
            self.fields['urg_flags'] = 0
            
            if stat.priority == 5: #TCP
                self.fields['L4_proto'] = 'tcp'
                self.fields['L4_src'] = stat.match['tcp_src']
                self.fields['L4_dst'] = stat.match['tcp_dst']
                  
                psh_flag_rule = [psh for psh in body if psh.table_id == 0 and
                                            psh.priority > 0 and 
                                            psh.match['in_port'] == stat.match['in_port'] and 
                                            psh.match['eth_dst'] == stat.match['eth_dst'] and
                                            psh.match['tcp_src'] == stat.match['tcp_src'] and
                                            psh.match['tcp_dst'] == stat.match['tcp_dst']]
                                            
                if psh_flag_rule:
                    self.fields['psh_flags'] = psh_flag_rule[0].stats['packet_count']
                                            
                
                urg_flag_rule = [urg for urg in body if urg.table_id == 1 and
                                            urg.priority > 0 and
                                            urg.match['in_port'] == stat.match['in_port'] and 
                                            urg.match['eth_dst'] == stat.match['eth_dst'] and
                                            urg.match['tcp_src'] == stat.match['tcp_src'] and
                                            urg.match['tcp_dst'] == stat.match['tcp_dst']]
                                            
                if urg_flag_rule:
                    self.fields['urg_flags'] = urg_flag_rule[0].stats['packet_count']
                                            
            if stat.priority == 4: #UDP
                self.fields['L4_proto'] = 'udp'
                self.fields['L4_src'] = stat.match['udp_src']
                self.fields['L4_dst'] = stat.match['udp_dst']                                
            
            self.logger.info('Entry\t%s\t%x\t%x\t%s\t%s\t%s\t%s\t%s\t%x\t%d\t%d\t%d\t%d',self.fields['time'],
                                                                                         self.fields['datapath'],
                                                                                         self.fields['in-port'],
                                                                                         self.fields['eth_src'],
                                                                                         self.fields['eth_dst'],
                                                                                         self.fields['L4_proto'],
                                                                                         self.fields['L4_src'],
                                                                                         self.fields['L4_dst'],
                                                                                         self.fields['out-port'],
                                                                                         self.fields['total_packets'],
                                                                                         self.fields['total_bytes'],
                                                                                         self.fields['psh_flags'],
                                                                                         self.fields['urg_flags'])
            

