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

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
		self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
		self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"
		self.arp_table["10.0.0.3"] = "00:00:00:00:00:03"
		self.arp_table["10.0.0.4"] = "00:00:00:00:00:04"

		if datapath.id == 3:
			print "Adding flows to switch 3"
			priority =5 
			self.add_flowss(datapath,priority,inet.IPPROTO_UDP,1,2)
	    		self.add_layer4_rules(datapath,priority+1,inet.IPPROTO_UDP,"10.0.0.2","10.0.0.3",None)
		if datapath.id == 1:
			print "Adding flows to switch 1"
			priority =5
			self.add_layer4_rules(datapath,priority,None,None,"10.0.0.1",3)
			self.add_layer4_rules(datapath,priority,None,None,"10.0.0.3",4)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_ICMP,None,"10.0.0.2",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_ICMP,None,"10.0.0.4",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_TCP,None,"10.0.0.2",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_TCP,None,"10.0.0.4",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_UDP,None,"10.0.0.2",1)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_UDP,None,"10.0.0.4",1)
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
					ip_proto = inet.IPPROTO_TCP,
					ipv4_src ="10.0.0.1",
					ipv4_dst = "10.0.0.3")
	        	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
	                                          ofproto.OFPCML_NO_BUFFER)]
	        	self.add_flow(datapath, priority+1, match, actions)
		if datapath.id == 2:
			print "Adding flows to switch 2"
			priority = 5
			self.add_layer4_rules(datapath,priority,None,None,"10.0.0.2",3)
			self.add_layer4_rules(datapath,priority,None,None,"10.0.0.4",4)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_ICMP,None,"10.0.0.1",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_ICMP,None,"10.0.0.3",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_TCP,None,"10.0.0.1",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_TCP,None,"10.0.0.3",2)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_UDP,None,"10.0.0.1",1)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_UDP,None,"10.0.0.3",1)
	 
    def add_layer4_rules(self,datapath,priority=1,ip_proto=None,ipv4_src=None,ipv4_dst=None,fwd_port=None):
		if ip_proto is None:
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_ICMP,ipv4_src,ipv4_dst,fwd_port)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_TCP,ipv4_src,ipv4_dst,fwd_port)
			self.add_layer4_rules(datapath,priority,inet.IPPROTO_UDP,ipv4_src,ipv4_dst,fwd_port)
			return
		parser = datapath.ofproto_parser
		if ipv4_src is None and ipv4_dst is None:
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
					ip_proto = ip_proto)
		elif ipv4_src is None:
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
					ip_proto = ip_proto,
					ipv4_dst =ipv4_dst)
		elif ipv4_dst is None:
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
					ip_proto = ip_proto,
					ipv4_src =ipv4_src)
		else:
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
					ip_proto = ip_proto,
					ipv4_src =ipv4_src,
					ipv4_dst = ipv4_dst)
		if fwd_port is None:
			actions = []
		else:
			actions = [parser.OFPActionOutput(fwd_port)]
		self.add_flow(datapath,priority,match,actions)

    def add_flowss(self,datapath,priority,protocol,port1,port2):
		parser = datapath.ofproto_parser
		match = parser.OFPMatch(in_port=port1,
					eth_type = ether.ETH_TYPE_IP,
					ip_proto = inet.IPPROTO_UDP)
		actions = [parser.OFPActionOutput(port2)]
		self.add_flow(datapath,priority,match,actions)
		match = parser.OFPMatch(in_port=port2,
					eth_type = ether.ETH_TYPE_IP,
					ip_proto = inet.IPPROTO_UDP)
		actions = [parser.OFPActionOutput(port1)]
		self.add_flow(datapath,priority,match,actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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

		#Reference how to identify the packet's protocols
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
		eth_type = eth.ethertype
	
		# process ARP
		if eth_type == ether.ETH_TYPE_ARP:
			self.handle_arp(datapath, in_port, pkt)
			return
		elif eth_type == ether.ETH_TYPE_IP:
			self.handle_ip(datapath, in_port, pkt)
			return
		else:
			return

    def handle_arp(self,datapath,in_port,pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		arp_pkt = pkt.get_protocol(arp.arp)
		arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]

		new_packet = packet.Packet()
		new_packet.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
				                       dst=eth_pkt.src,
						       src=arp_resolv_mac))
		new_packet.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
				             src_mac=arp_resolv_mac,
					     src_ip=arp_pkt.dst_ip,
					     dst_mac=arp_pkt.src_mac,
					     dst_ip=arp_pkt.src_ip))
		new_packet.serialize()
		actions = [parser.OFPActionOutput(in_port)]
		out = parser.OFPPacketOut(datapath,
					  ofproto.OFP_NO_BUFFER,
			                  ofproto.OFPP_CONTROLLER,
	                                  actions,
	                                  new_packet.data)
		datapath.send_msg(out)

    def handle_ip(self,datapath,in_port,pkt):
		ofproto=datapath.ofproto
		parser = datapath.ofproto_parser

		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		ipv4_pkt = pkt.get_protocol(ipv4.ipv4) 
		if datapath.id == 1 and ipv4_pkt.proto==inet.IPPROTO_TCP:
	    tcp_pkt = pkt.get_protocol(tcp.tcp) 
	    new_packet = packet.Packet()
	    new_packet.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
			                           dst=eth_pkt.src,
					           src=eth_pkt.dst))
	    new_packet.add_protocol(ipv4.ipv4(dst=ipv4_pkt.src,
					       src=ipv4_pkt.dst,
					       proto=ipv4_pkt.proto))
	    new_packet.add_protocol(tcp.tcp(src_port=tcp_pkt.dst_port,
					 dst_port=tcp_pkt.src_port,
					 ack=tcp_pkt.seq+1,
					 bits=20))	    
	    new_packet.serialize()
	    actions = [parser.OFPActionOutput(in_port)]
	    out = parser.OFPPacketOut(datapath,
				  ofproto.OFP_NO_BUFFER,
		                  ofproto.OFPP_CONTROLLER,
                                  actions,
                                  new_packet.data)
	    datapath.send_msg(out)