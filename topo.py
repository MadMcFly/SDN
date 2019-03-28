from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import info,setLogLevel
from mininet.node import RemoteController
from mininet.node import CPULimitedHost
from mininet.link import TCLink

class CustomizedTopo(Topo):
	"topo for lab4:controller"
	def build(self):

		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		s3 = self.addSwitch('s3')
		s4 = self.addSwitch('s4')

		
		h1 = self.addHost('h1', ip = '10.0.0.1/24', mac = '00:00:00:00:00:01')
		h2 = self.addHost('h2', ip = '10.0.0.2/24', mac = '00:00:00:00:00:02')
		h3 = self.addHost('h3', ip = '10.0.0.3/24', mac = '00:00:00:00:00:03')
		h4 = self.addHost('h4', ip = '10.0.0.4/24', mac = '00:00:00:00:00:04')
		
		self.addLink(h1, s1, 1, 1)
		self.addLink(h2, s2, 1, 1)
		self.addLink(h3, s3, 1, 1)
		self.addLink(h4, s4, 1, 1)
		self.addLink(s1, s2, 2, 2)
		self.addLink(s1, s4, 3, 2)
		self.addLink(s2, s3, 3, 2)
		self.addLink(s3, s4, 3, 3)
	
topos = { 'mytopo': ( lambda: CustomizedTopo()) }

'''def test():
	topo = CustomizedTopo()
	net = Mininet(topo = topo, host = CPULimitedHost, link = TCLink, controller = OVSController)
	net.start()
	dumpNodeConnections(net.hosts)
	net.pingAll()
	net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	test()'''