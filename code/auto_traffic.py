import os 
import random
from optparse import OptionParser

def auto_run(options):
    server_addr = options.srv_addr
    server_port = options.srv_port
    request_ival = options.req_ival
    request_times = options.req_times
    load_range = options.load_range

    load_range = eval(load_range)
    assert(isinstance(load_range, list))
    for _ in range(request_times):
        once_times = 5
        os.system('ping %s -c 3' %server_addr)
        loads = random.randint(load_range[0], load_range[1])
        os.system('iperf -c %s -u -p %d -b %dM -i %d -t %d' %(
            server_addr, server_port, loads, request_ival, once_times))

if __name__ == '__main__':
    prompt = '''usage: %prog  -a srv_addr -p srv_port -i req_ival -t req_times -l [40,45]'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-a', '--srv_addr', dest='srv_addr')
    parser.add_option('-p', '--srv_port', dest='srv_port', type="int")
    parser.add_option('-i', '--req_ival', dest='req_ival', type="int", default=1)
    parser.add_option('-t', '--req_times', dest='req_times', type="int", default=3)
    parser.add_option('-l', '--load_range', dest='load_range', type="str")
    
    (options, args) = parser.parse_args()
    auto_run(options)