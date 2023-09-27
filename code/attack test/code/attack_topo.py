from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from optparse import OptionParser
import math 

# A linear topo with 5 switches is the base. 
class BaseTopo(Topo):
    def __init__(self, num_sw=5, bw=100, delay='5ms', max_queue_size=1000000):
        super(BaseTopo, self).__init__(self)
        switches = []
        for i in range(1, num_sw + 1):
            si = self.addSwitch('s%d'%i)
            hi = self.addHost('h%d'%i)
            self.addLink(hi, si, bw=bw, delay=delay, max_queue_size=max_queue_size)
            switches.append(si)
            if i > 1:
                self.addLink(si, switches[i-2], bw=bw, delay=delay, max_queue_size=max_queue_size)

class FL_Injector:
    def __init__(self, net, num_sw, num_fl, bw, delay, inj):
        self.net = net
        self.num_sw = num_sw 
        self.num_fl = num_fl
        self.bw = bw
        self.delay = delay
        self.inj = inj

    def select_fake_links(self):
        fake_links = []
        div_domain = (self.num_sw - 2) // 3
        if div_domain < self.num_fl:
            return fake_links
        for i in range(div_domain):
            if i >= self.num_fl:
                break
            fake_links.append(3 * i + 1)
        return fake_links

    def add_exp_switch(self, idx, bw, delay):
        exp_s = self.net.addSwitch('s%d'%(100+idx))
        self.net.addLink(exp_s, self.net.get('s%d'%idx), bw=bw, delay=delay)
        
    def inject_fake_links(self, fake_links):
        if len(fake_links) == 0:
            return False
        for idx in fake_links:
            src_idx = idx+1
            dst_idx = idx+3
            print('[+] Injecting link h%d <-> h%d' %(src_idx, dst_idx))
            host_src = self.net.get('h%d'%(src_idx))
            host_dst = self.net.get('h%d'%(dst_idx))
            self.net.addLink(host_src, host_dst, bw=self.bw/2, delay=self.delay)
            if self.inj:
                # exp switches for verification
                self.add_exp_switch(src_idx, bw=self.bw, delay=self.delay)
                self.add_exp_switch(dst_idx, bw=self.bw, delay=self.delay)
                host_src.popen('ifconfig h%d-eth0 0.0.0.0' %(src_idx))
                host_src.popen('ifconfig h%d-eth1 0.0.0.0' %(src_idx))
                host_dst.popen('ifconfig h%d-eth0 0.0.0.0' %(dst_idx))
                host_dst.popen('ifconfig h%d-eth1 0.0.0.0' %(dst_idx))
                host_src.popen('python3 %s -i h%d-eth0 -o h%d-eth1 -a 1'%(self.inj, src_idx, src_idx))
                host_src.popen('python3 %s -i h%d-eth1 -o h%d-eth0 -a 1'%(self.inj, src_idx, src_idx))
                host_dst.popen('python3 %s -i h%d-eth0 -o h%d-eth1 -a 1'%(self.inj, dst_idx, dst_idx))
                host_dst.popen('python3 %s -i h%d-eth1 -o h%d-eth0 -a 1'%(self.inj, dst_idx, dst_idx))
        return True 

    def config_normal_hosts(self):
        normal_hosts = list(range(1, self.num_sw + 1))
        fake_links = self.select_fake_links()
        for idx in fake_links:
            normal_hosts.remove(idx+1)
            normal_hosts.remove(idx+3)
        
        for idx in normal_hosts:
            host = self.net.get('h%d' %idx)
            host.popen('ethtool -K h%d-eth0 tx off' %idx)
            host.popen('ethtool -K h%d-eth0 rx off' %idx) 

# topos = {'custom': (lambda: BaseTopo())}
def construct_topo(options):
    ctrl_ip = options.ctrl_ip
    ctrl_port = options.ctrl_port 
    num_sw = options.num_sw
    num_fl = options.num_fl
    bw = options.bw
    delay = options.delay
    inj = options.inj
    # contruct base topo without fake links.
    setLogLevel('info')
    topo = BaseTopo(num_sw=num_sw, bw=bw, delay=delay)
    controller = RemoteController('c0', ip=ctrl_ip, port=ctrl_port)
    net = Mininet(topo=topo, controller=controller, link=TCLink)
    # inject out-of-band link.
    fl_inj = FL_Injector(net, num_sw, num_fl, bw, delay, inj)
    fake_links = fl_inj.select_fake_links()
    if len(fake_links) == 0:
        print('[+] Have not Inject fake links!')
    else:
        print('[+] Inject %d fake links' %len(fake_links))
        fl_inj.inject_fake_links(fake_links)
    fl_inj.config_normal_hosts()
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    prompt = '''usage: %prog  -i in_dev ip -o out_dev'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-a', '--ctrl_ip', dest='ctrl_ip', type="str", default='127.0.0.1')
    parser.add_option('-p', '--ctrl_port', dest='ctrl_port', type="int", default=6653)
    parser.add_option('-s', '--num_sw', dest='num_sw', type="int", default=5)
    parser.add_option('-f', '--num_fl', dest='num_fl', type="int", default=1)
    parser.add_option('-b', '--bw', dest='bw', type="int", default=100)
    parser.add_option('-t', '--delay', dest='delay', type="str", default='0.5ms')
    parser.add_option('-i', '--inj', dest='inj', type="str", default='')
    (options, args) = parser.parse_args()
    construct_topo(options)
