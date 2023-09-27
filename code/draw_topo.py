from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from optparse import OptionParser

# A linear topo with 5 switches is the base. 
class DrawTopo(Topo):
    def __init__(self):
        super(DrawTopo, self).__init__(self)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, s2)
        self.addLink(s3, h3)
        self.addLink(s3, h4)
        self.addLink(s3, s2)
        self.addLink(h2, h4)
       

def inject_link(net, src_idx, dst_idx, inj_file):
    host_src = net.get('h%d'%(src_idx))
    host_dst = net.get('h%d'%(dst_idx))
    net.addLink(host_src, host_dst)
    host_src.popen('ifconfig h%d-eth0 0.0.0.0' %(src_idx))
    host_src.popen('ifconfig h%d-eth1 0.0.0.0' %(src_idx))
    host_dst.popen('ifconfig h%d-eth0 0.0.0.0' %(dst_idx))
    host_dst.popen('ifconfig h%d-eth1 0.0.0.0' %(dst_idx))
    host_src.popen('python3 %s -i h%d-eth0 -o h%d-eth1 -a 1'%(inj_file, src_idx, src_idx))
    host_src.popen('python3 %s -i h%d-eth1 -o h%d-eth0 -a 1'%(inj_file, src_idx, src_idx))
    host_dst.popen('python3 %s -i h%d-eth0 -o h%d-eth1 -a 1'%(inj_file, dst_idx, dst_idx))
    host_dst.popen('python3 %s -i h%d-eth1 -o h%d-eth0 -a 1'%(inj_file, dst_idx, dst_idx))

# topos = {'custom': (lambda: BaseTopo())}
def construct_topo(options):
    ctrl_ip = options.ctrl_ip
    ctrl_port = options.ctrl_port 
    inj_file = options.inj
    # contruct base topo without fake links.
    setLogLevel('info')
    topo = DrawTopo()
    controller = RemoteController('c0', ip=ctrl_ip, port=ctrl_port)
    net = Mininet(topo=topo, controller=controller, link=TCLink)
    if len(inj_file) > 0:
        inject_link(net, options.src, options.dst, inj_file)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    prompt = '''usage: %prog  -i outband_lldp_relay_attack.py'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-a', '--ctrl_ip', dest='ctrl_ip', type="str", default='127.0.0.1')
    parser.add_option('-p', '--ctrl_port', dest='ctrl_port', type="int", default=6653)
    parser.add_option('-i', '--inj', dest='inj', type="str", default='')
    parser.add_option('-s', '--src', dest='src', type="int", default='2')
    parser.add_option('-d', '--dst', dest='dst', type="int", default='4')
    
    (options, args) = parser.parse_args()
    construct_topo(options)
