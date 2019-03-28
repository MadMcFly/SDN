from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.log import info, setLogLevel

class FatTree(Topo):
	"Fat-Tree with switch port number k(k is even)"
	#def build(self):
	def build(self, k):
		print k
		#k = 6
		podNum = k
		hostNum = k * (k / 2)
		edgeSwitchNum = k
		coreSwitchNum = k / 2
		
		coreSwitches = []
		edgeSwitches = []

		for core in range(0, coreSwitchNum):
			coreSwitches.append(self.addSwitch("cs_" + str(core)))

		for pod in range(0, podNum):

			for edge in range(0, edgeSwitchNum / podNum):
				edgeThis = self.addSwitch("es_" + str(pod))
				edgeSwitches.append(edgeThis)
				
				for x in range(0, coreSwitchNum):
					self.addLink(edgeThis, coreSwitches[x])

				for x in range(0, hostNum / podNum / (edgeSwitchNum / podNum)):
					self.addLink(edgeThis, self.addHost("h_" + str(pod) + "_" + str(x)))


#topos = { 'mytopo': ( lambda: FatTree()) }


if __name__ == '__main__':	
	setLogLevel('info')
	print "type switch port number(even):"
	k = input()
	topo = FatTree(k)
	net = Mininet(topo = topo, controller = OVSController)
	net.start()
	net.stop()