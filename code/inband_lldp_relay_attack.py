import pcap
import dpkt
import socket
import psutil 
import time 
from optparse import OptionParser

class LLDPRelayClient(object):
    '''
    bind_iface: the binding interface to sniff LLDP packets.
    relay_ends: relay the LLDP to the ends through UDP sockets. 
    '''
    def __init__(self, bind_iface, relay_addr):
        self.bind_iface = bind_iface 
        self.relay_addr = relay_addr
        self.relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local_mac = self._query_mac(bind_iface)
        print(self.local_mac)
    
    def _query_mac(self, iface):
        addr_dict = psutil.net_if_addrs()    
        if iface not in addr_dict:
            return '00:00:00:00:00:00' 
        for snic_addr in addr_dict[iface]:
            if snic_addr.family.name == 'AF_PACKET':
                return snic_addr.address
        return '00:00:00:00:00:00' 
            
    def _init_pcap(self):
        pcap_handler = pcap.pcap(self.bind_iface, promisc=False, immediate=True, timeout_ms=50)
        filter_strategy = 'inbound and \
                (ether proto 0x88cc or \
                (not ether dst host ff:ff:ff:ff:ff:ff and \
                 not ether src host 00:00:de:ad:be:ef))' 
        pcap_handler.setfilter(filter_strategy)
        return pcap_handler
    
    def _loop_capture(self, pcap_handler):
        for ptime, pdata in pcap_handler:
            eth = dpkt.ethernet.Ethernet(pdata)
            dst_mac = eth.dst
            str_dst_mac = ':'.join(['{:02x}'.format(n) for n in dst_mac])
            if str_dst_mac == self.local_mac:
                continue
            self.relay_sock.sendto(pdata, self.relay_addr)
            # delta_time = time.time() - ptime 
            # print(f'capturing delay {delta_time}')

    def run(self):
        try:
            pcap_handler = self._init_pcap()
            self._loop_capture(pcap_handler)
        except KeyboardInterrupt:
            return 

class LLDPRelayServer(object):
    '''
    bind_addr: the binding socket address to recv LLDP packets. 
        say, ('192.168.1.1', 8080)
    relay_iface: relay the LLDP to the switch through pcap. 
    '''
    def __init__(self, bind_addr, bind_iface):
        self.bind_addr = bind_addr
        self.bind_iface = bind_iface
        self.recv_sock = self._init_recv_sock()
        self.pcap_handler = self._init_pcap()
        
    def _init_recv_sock(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(self.bind_addr)
        except socket.error as e:
            print(e)
            return None 
        else:
            print('[+] recv sock is successfully initialized.')
            return sock

    def _init_pcap(self):
        return pcap.pcap(self.bind_iface, promisc=False, immediate=True, timeout_ms=50)

    def _process(self):
        recv_data, recv_addr = self.recv_sock.recvfrom(65535)
        recv_size = len(recv_data)
        print(f'recved from {recv_addr}: {recv_size} bytes.')
        # NOTE: 
        # 1. In-band LFA is not robust, because the mac or ip address of relayed hosts
        # and relayed packets are inconsistent, which makes it easy to be detected. In 
        # addition, the inconsistency makes fake link unstable, because each time the flow entry
        # is timeout, the in-band channel would be disrrupted. At this event, if the flow entry is
        # updated with the relayed packets, the in-band channel would be closed, because relayed 
        # hosts are disconnected. 
        # 2. Therefore, to collect the link delay of in-band channel, we must set idle_timeout value.
        self.pcap_handler.sendpacket(recv_data)

    def run(self):
        while True:
            try:
                self._process()
            except KeyboardInterrupt as e:
                break
        
if __name__ == '__main__':
    prompt = '''usage: %prog -t [c|s] -i iface -a ip -p port.'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-t', '--type', dest='type')
    parser.add_option('-i', '--iface', dest='iface')
    parser.add_option('-a', '--addr', dest='addr', default='0.0.0.0')
    parser.add_option('-p', '--port', dest='port', type="int")
    (options, args) = parser.parse_args()

    app_type = options.type.upper()
    if app_type == 'C':
        client = LLDPRelayClient(
            options.iface,
            (options.addr, options.port))
        client.run()
    elif app_type == 'S':
        server = LLDPRelayServer(
            (options.addr, options.port), 
            options.iface)
        server.run()
    else:
        print(parser.usage)

