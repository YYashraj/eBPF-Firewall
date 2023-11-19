from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController

class CustomTopology(Topo):
    def build(self):
        # Adding switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')

        # Adding hosts
        host1 = self.addHost('h1', ip='10.0.0.1/24')
        host2 = self.addHost('h2', ip='10.0.0.2/24')
        host3 = self.addHost('h3', ip='10.0.0.3/24')
        host4 = self.addHost('h4', ip='10.0.0.4/24')

        # Creating links
        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch2)
        self.addLink(host4, switch2)
        self.addLink(switch1, switch2)

topo = CustomTopology()

net = Mininet(topo=topo)
net.start()
CLI(net)
net.stop()


