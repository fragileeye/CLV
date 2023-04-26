# CLV
Correlated link based OOB-LFA detection
The structure of the files is as follows:

+ [D] 3cases: show the distribution of measured delay in varying cases
+ [D] corr_links_quality: show the measured link quality in varying cases
+ [D] snapshot: show how clv works and the stat features of entropy and #K
+ [D] compare: compare clv with related methods, and show the performance in varying network scales, fake links as well as tx delays  
+ [F] auto_traffic.py: generate background traffic with iperf
+ [F] base_topo.py: generate topology with varying switches, fake links as well as tx delays in Mininet
+ [F] inband_lldp_relay_attack.py: ignored in CLV, but can be used to test for your own experiment as you wish
+ [F] link_logger.py: collect link data (link delay, link loads) in Ryu
+ [F] outband_lldp_relay_attack.py: out-of-band relay module implemented with Pypcap
+ [F] outband_lldp_relay_attack_app.py: out-of-band relay module implemented with Scapy
+ [F] spot.py: calculate the threshold of entropy, see also [SPOT](https://github.com/Amossys-team/SPOT).
+ [D] dataset: compressed txt files which record the link data, such as {src_link -> dst_link d_cs d_sc d_l, load}
