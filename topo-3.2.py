#!/usr/bin/python

'''meh'''

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController, Host, OVSSwitch
from mininet.link import Link
from mininet.log import setLogLevel,info

NUM_SWITCH_CONNECTIONS = 4

class MyTopo( Topo ):
	def __init__( self ):
		
		if(NUM_SWITCH_CONNECTIONS % 2 == 1):
			print ("Error! NUM_SWITCH_CONNECTIONS is an odd number!")
			return

		if(NUM_SWITCH_CONNECTIONS < 4):
			print ("Error! NUM_SWITCH_CONNECTIONS is less than 4.")
		
		Topo.__init__( self )

		# Add hosts and switches
		num_hosts = NUM_SWITCH_CONNECTIONS
		host_num              = 0
		switch_num            = 0
		curr_edge_switch      = ''
		curr_host             = ''
		half_connection_count = NUM_SWITCH_CONNECTIONS // 2

		# Establish core switches
		for core_switch_num in range(NUM_SWITCH_CONNECTIONS):
			self.addSwitch( 'cs{0}'.format(core_switch_num) )
		# Establish each pod & build links
		for i in range(NUM_SWITCH_CONNECTIONS):
			for j in range(half_connection_count):
				pod_edge_switch = self.addSwitch( 'es{0}'.format(switch_num + j) )
				self.addLink( pod_edge_switch, 'cs{0}'.format(j) ) 
				self.addLink( pod_edge_switch, 'cs{0}'.format(j + half_connection_count) )
				for k in range(NUM_SWITCH_CONNECTIONS - 2):
					host = self.addHost( 'h{0}'.format(host_num) )
					self.addLink( pod_edge_switch, host )
					host_num += 1
			switch_num += half_connection_count

topos = { 'mytopo' : ( lambda: MyTopo() ) }
