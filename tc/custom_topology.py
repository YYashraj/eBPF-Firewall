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
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        # Creating links
        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch2)
        self.addLink(host4, switch2)
        self.addLink(switch1, switch2)

topo = CustomTopology()

# Explicitly specify the controller IP and port in RemoteController
controller = RemoteController('c0', ip='127.0.0.1', port=6633)
net = Mininet(topo=topo, controller=controller, waitConnected=True)
net.start()
CLI(net)
net.stop()


