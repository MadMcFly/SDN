#!/usr/bin/python

'''meh'''

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController, Host, OVSSwitch
from mininet.link import Link
from mininet.log import setLogLevel,info

class MyTopo( Topo ):
	def __init__( self ):

		Topo.__init__( self )

		# Add hosts and switches
		h1 = self.addHost( 'h1' )
		h2 = self.addHost( 'h2' )
		sA = self.addSwitch( 's1' )
		sB = self.addSwitch( 's2' )
		sC = self.addSwitch( 's3' )
		sD = self.addSwitch( 's4' )
		sE = self.addSwitch( 's5' )

		# Add links
		self.addLink( h1, sA )
		self.addLink( sA, sB )
		self.addLink( sA, sC )
		self.addLink( sB, sD )
		self.addLink( sB, sE )
		self.addLink( sC, sD )
		self.addLink( sC, sE )
		self.addLink( sD, h2 )
		self.addLink( sD, sE )

topos = { 'mytopo' : ( lambda: MyTopo() ) }

#def makeTopo():
#	MyTopo()
#	c1 = Controller( 'c1' )

#if __name__ == '__main__':
#	setLogLevel('info')
#	makeTopo()

