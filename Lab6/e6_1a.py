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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from operator import attrgetter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.lib import hub
import matplotlib.pyplot as plt
import numpy as np
import time

TRAFFIC_UPDATE_PERIOD = 10
PORT_MAX = 32

def find_min_length(data):
    min = 10000000000000
    for switch in data.values():
        for port_data in switch.values():
            if(len(port_data) < min):
                min = len(port_data)
    return min

def graph_results(data, duration, spacing, set_width, set_height):
    '''Given a data input and a duration (in seconds), creates a graph from the data.'''
    subplot_id = 100 * set_height + 10 * set_width + 1
    count = 1
    # num_range = np.arange(0, duration, spacing)
    min_range = find_min_length(data)
    num_range = np.arange(0, duration, duration / min_range)
    print len(data[1][1])
    print('a')
    for switch in data.values():
        port_count = 1
        plt.subplot(subplot_id)
        print('b')
        for port_data in switch.values():
            print("min_length is {}, length of port data is {}".format(min_range, len(port_data)))
            abridged_data = port_data[len(port_data)-min_range:len(port_data)]
            plt.plot(num_range, abridged_data, label="Port {}".format(port_count))
            port_count += 1
        plt.title("Switch S{}".format(count))
        plt.legend()
        plt.xlabel("Time (s)")
        plt.ylabel("Throughput (bytes/s)")
        subplot_id += 1
        count += 1
    plt.suptitle("Traffic Rates of all Switches")
    plt.show()

class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.start_time = time.time()
        self.graph_made = False
        self.traffic_rates = {}
        self.rate_snapshots = {}
        #self.previous_values = [ [ { } ], [ { } ], [ { } ], [ { } ], [ { } ] ]
        self.previous_values = {}
        self.stat_start = {}
        self.flag = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        dpid = datapath.id  # classifying the switch ID
        

        if dpid == 1: # switch S1
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.1', 10, 1)
            self.add_layer4_rules(datapath, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, '10.0.0.3', 10, 3)
  
        if dpid == 3: # switch S3
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.1', 10, 1)
            self.add_layer4_rules(datapath, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, '10.0.0.3', 10, 2)

        if dpid == 4: # switch S4
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.2', 10, 1)
            self.add_layer4_rules(datapath, '10.0.0.3', 10, 2)

        if dpid == 5: # switch S5
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.3', 10, 1)

    def add_layer4_rules(self, datapath, ipv4_dst = None, priority = 1, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ipv4_dst = ipv4_dst)
        self.add_flow(datapath, priority, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

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
            if ( (time.time() - self.start_time >= 600.0) and (not self.graph_made) ): #10 minutes
                self.graph_made = True
                self.logger.info(self.traffic_rates)
                print("\n")
                graph_results(self.traffic_rates, 600.0, TRAFFIC_UPDATE_PERIOD, 3, 2)
            hub.sleep(TRAFFIC_UPDATE_PERIOD - ((time.time() - self.start_time) % 10))    

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('tx_bytes')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             dpid, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            if stat.port_no == 2:
                flag[dpid] = True
            else:
                flag[dpid] = False

            if stat.port_no <= PORT_MAX:
                if dpid not in self.stat_start:
                    self.stat_start[dpid] = False
                traffic_rate = stat.rx_bytes + stat.tx_bytes
                if dpid not in self.rate_snapshots:
                    self.rate_snapshots[dpid] = {}
                self.rate_snapshots[dpid][stat.port_no] = traffic_rate
                
                if self.stat_start[dpid]:
                    byte_delta = self.rate_snapshots[dpid][stat.port_no] - self.previous_values[dpid][stat.port_no]
                else:
                    byte_delta = traffic_rate
                    
                data_rate = byte_delta / TRAFFIC_UPDATE_PERIOD
                if dpid not in self.traffic_rates:
                    self.traffic_rates[dpid] = {}
                if stat.port_no not in self.traffic_rates[dpid]:
                    self.traffic_rates[dpid][stat.port_no] = []
                # if self.stat_start[dpid]:
                    # self.logger.info('Inserting %8d - %8d = %8d / %2d  into traffic_rates[%1d][%1d]',
                    #                  self.rate_snapshots[dpid][stat.port_no],
                    #                  self.previous_values[dpid][stat.port_no],
                    #                  byte_delta, TRAFFIC_UPDATE_PERIOD, dpid, stat.port_no)
                # else:
                    # self.logger.info('Inserting %8d / %2d  into traffic_rates[%1d][%1d]',
                    #                  byte_delta, TRAFFIC_UPDATE_PERIOD, dpid, stat.port_no)
                self.traffic_rates[dpid][stat.port_no].append(data_rate)
        self.previous_values[dpid] = self.rate_snapshots[dpid]
        # print("[]\n".format(self.previous_values))
        self.rate_snapshots[dpid] = {}
        self.stat_start[dpid] = True
        # if self.stat_start:
        #     while True:
        #         hub.sleep(TRAFFIC_UPDATE_PERIOD)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype    
        if in_port == 1 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            if flag[datapath]:
                fwd_port = 3
            else:
                fwd_port = 2
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(fwd_port)]
            tcp_pkt = pkt.get_protocol(tcp.tcp) # parser out the TCP pkt
            match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                    ip_proto = ip_proto,
                                    ipv4_dst = ipv4_dst,
                                    tcp_dst = tcp_pkt.dst_port)
            self.add_flow(datapath, priority, match, actions)
        if in_port == 3 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            if flag:
                fwd_port = 1
            else:
                fwd_port = 2
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(fwd_port)]
            tcp_pkt = pkt.get_protocol(tcp.tcp) # parser out the TCP pkt
            match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                    ip_proto = ip_proto,
                                    ipv4_dst = ipv4_dst,
                                    tcp_dst = tcp_pkt.dst_port)
            self.add_flow(datapath, priority, match, actions)    
    
        if ethertype == ether.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            udp_pkt = pkt.get_protocol(udp.udp)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            
        if (datapath.id == 1 and ipv4_pkt.proto == inet.IPPROTO_UDP):
                #H1 to H2
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
                
                #H1 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(3)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
                
                #H2 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(3)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
        elif (datapath.id == 3 and ipv4_pkt.proto == inet.IPPROTO_UDP):
                #H1 to H2
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
                
                #H1 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
        elif (datapath.id == 4 and ipv4_pkt.proto == inet.IPPROTO_UDP):
                #H1 to H2
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
                
                #H2 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
        elif (datapath.id == 4 and ipv4_pkt.proto == inet.IPPROTO_UDP):
                #H1 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
                
                #H2 to H3
                match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.3',
                                        udp_dst = udp_pkt.dst_port,
                                        udp_src = udp_pkt.src_port,
                                        ip_proto = inet.IPPROTO_UDP)
                actions = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 65535, match, actions)

                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions,
                                      msg.data)
                datapath.send_msg(out)
