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
        dpid = datapath.id  # classifying the switch ID    
                      
        if dpid == 4: # switch S4
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.1', 10, 1)
            #self.add_layer4_rules(datapath, '10.0.0.2', 10, 2)

        elif dpid == 5: # switch S5
            ### implement tcp fwding
            self.add_layer4_rules(datapath, '10.0.0.2', 10, 1)
            #self.add_layer4_rules(datapath, '10.0.0.1', 10, 2)
            ### send TCP from 10.0.0.4 to 10.0.0.2 to controller
            #match1 = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_src='10.0.0.4',ipv4_dst='10.0.0.2',ip_proto=inet.IPPROTO_TCP)
            #actions1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            #self.add_flow(datapath,30,match1,actions1)
        else:
            print "wrong switch"

    # Member methods you can call to install TCP/UDP/ICMP fwding rules
    def add_layer4_rules(self, datapath, ipv4_dst = None, priority = 1, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ipv4_dst = ipv4_dst)
        self.add_flow(datapath, priority, match, actions)

    # Port dependent variant
    def add_layer4_port_dependent_rules(self, datapath, ipv4_dst, priority, fwd_port, d_port, s_port):
        print('{} {} {} {} {}').format(ipv4_dst, 10, fwd_port, d_port, s_port)
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ipv4_dst = ipv4_dst,
                                ip_proto = 6,
                                tcp_dst  = d_port,
                                tcp_src  = s_port)
        self.add_flow(datapath, priority, match, actions)

    def add_layer4_drop_rule(self, datapath, ip_proto, priority = 1):
        parser = datapath.ofproto_parser
        actions = []
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src = eth_pkt.src
        dst = eth_pkt.dst
        
        in_port = msg.match['in_port']
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        if ethertype == ether.ETH_TYPE_IP: #IP packet
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt.proto == inet.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                d_port = tcp_pkt.dst_port
                s_port = tcp_pkt.src_port
                if dpid in [1, 2, 3]: # switch S1, S2, S3
                    ### implement tcp fwding
                    self.add_layer4_port_dependent_rules(datapath, '10.0.0.1', 10, 1, s_port, d_port)
                    self.add_layer4_port_dependent_rules(datapath, '10.0.0.2', 10, 2, d_port, s_port)
                    actions = [parser.OFPActionOutput(out_port)]
                elif (dpid in [4, 5]) and (in_port == 1): # switches S4, S5
                    ### rotate destinations based on round robin sequence
                    if (dpid == 4):
                        via_port = (s_port % 3) + 2
                        ip_dst = '10.0.0.2'
                    else:
                        via_port = (d_port % 3) + 2
                        ip_dst = '10.0.0.1'
                    self.add_layer4_port_dependent_rules(datapath, ip_dst, 10, via_port, d_port, s_port)
                    actions = [parser.OFPActionOutput(via_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
                datapath.send_msg(out)
                    
                       

        # process ARP 
        elif ethertype == ether.ETH_TYPE_ARP:
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
            arp_hd = arp.arp(hwtype = 1,proto=0x0800, hlen=6, plen=4, opcode=2,src_mac=arp_resolv_mac, src_ip=arp_pkt.dst_ip,dst_mac=eth_pkt.src, dst_ip=arp_pkt.src_ip);
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
