# CLV
Correlated link based LFA detection

## Description of code
+ [D] 3cases: show the distribution of measured delay in varying cases
+ [D] corr_links_quality: show the measured link quality in varying cases
+ [D] snapshot: show how clv works, see the distribution of entropy and #K
+ [D] compare: compare clv with related methods, and show the performance in varying network scales, fake links as well as tx delays  
+ [F] auto_traffic.py: generate background traffic with iperf
+ [F] base_topo.py: generate topology with varying switches, fake links as well as tx delays in Mininet
+ [F] ctrl_flood.py: overload Ryu controller via fake mac flooding   
+ [F] inband_lldp_relay_attack.py: ignored in CLV, but can be used to test for your own experiment as you wish
+ [F] link_logger.py: collect link data (link delay, link loads) based on Ryu
+ [F] outband_lldp_relay_attack.py: out-of-band relay module implemented with Pypcap
+ [F] outband_lldp_relay_attack_app.py: out-of-band relay module implemented with Scapy
+ [F] spot.py: calculate the threshold of entropy, see also [SPOT](https://github.com/Amossys-team/SPOT) (invalid now?) or [EVT](https://github.com/DawnsonLi/EVT) or other SPOT operation in github.
+ [F] switch_lldp_relay_attack.py: switch-based relay attack via modify flow rules.

## Description of dataset
+ dataset: compressed txt files which record raw link data, such as {src_link -> dst_link d_cs d_sc d_l, load}

## Please note
+ It is time-consuming to make the dataset, because there are too many situation need to be considered except writing the code.  
+ We must confess that the dataset may be insufficient to cover all possible LFA cases, because it's only generated in our computer with limited parameters, such as volumn of background traffic, attack rate, etc. Nevertheless, we try our best to do the job and are willing to share our work.
+ For more details, please refer to [A novel link fabrication attack detection method for low-latency SDN networks](https://doi.org/10.1016/j.jisa.2024.103807)
