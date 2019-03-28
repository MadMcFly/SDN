from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.arp_table = {}

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
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

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

        # process ARP 
        if ethertype == ether.ETH_TYPE_ARP:
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            arp_pkt = pkt.get_protocol(arp.arp)
            # obtain the MAC of dst IP  
            arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]

            ### generate the ARP reply msg, please refer RYU documentation
            ### the packet library section

            ### hint: ether_hd = ethernet.ethernet(dst = eth_pkt.src, 
            ###                      src = arp_resolv_mac,
            ###                      ethertype = ether.ETH_TYPE_ARP);
            ###       arp_hd = arp.arp(hwtype = 1, ...
            ###       arp_reply = packet.Packet();
            ###       arp_reply.add_protocol(ether_hd)
            ###       ...
                
            ether_hd = ethernet.ethernet(dst = eth_pkt.src,src = arp_resolv_mac,ethertype = ether.ETH_TYPE_ARP);
            arp_hd = arp.arp(hwtype = 1,proto=0x0800, hlen=6, plen=4, opcode=2,
                src_mac=arp_resolv_mac, src_ip=arp_pkt.dst_ip,
                dst_mac=eth_pkt.src, dst_ip=arp_pkt.src_ip);
            arp_reply = packet.Packet();
            arp_reply.add_protocol(ether_hd);
            arp_reply.add_protocol(arp_hd);
            arp_reply.serialize();

            
            # send the Packet Out mst to back to the host who is initilaizing the ARP
            actions = [parser.OFPActionOutput(in_port)];
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                      ofproto.OFPP_CONTROLLER, actions,
                                      arp_reply.data)
            datapath.send_msg(out)

        if ethertype == ether.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4) # parse out the IPv4 pkt
            if ipv4_pkt.proto == inet.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp) # parser out the TCP pkt
                if datapath.id == 4:
                    if(ipv4_pkt.src == '10.0.0.1'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(2)]
                        self.add_flow(datapath, 10, match, actions)
                    elif(ipv4_pkt.src == '10.0.0.2'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.1',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(1)]
                        self.add_flow(datapath, 10, match, actions)

                elif datapath.id == 5:
                    if(ipv4_pkt.src == '10.0.0.1'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(1)]
                        self.add_flow(datapath, 10, match, actions)
                    elif(ipv4_pkt.src == '10.0.0.2'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.1',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(2)]
                        self.add_flow(datapath, 10, match, actions)

                else:
                    if(ipv4_pkt.src == '10.0.0.1'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.1',
                                        ipv4_dst = '10.0.0.2',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(2)]
                        self.add_flow(datapath, 10, match, actions)
                    elif(ipv4_pkt.src == '10.0.0.2'):
                        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                        ip_proto = ip_proto,
                                        ipv4_src = '10.0.0.2',
                                        ipv4_dst = '10.0.0.1',
                                        tcp_src = tcp_pkt.src_port,
                                        tcp_dst = tcp_pkt.dst_port)
                        actions = [parser.OFPActionOutput(1)]
                        self.add_flow(datapath, 10, match, actions)