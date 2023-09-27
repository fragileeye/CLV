from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import hub
from ryu.topology.api import *
from ryu.topology.event import *
import time
import struct 
import numpy as np
import sys 

class LinkLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MONITOR_WINDOW_SIZE = 3
    MONITOR_LOADS_IVAL = 2
    MONITOR_DELAY_IVAL = 2
    MONITOR_PROBE_ADDRESS = '1.1.1.1'
    MONITOR_CTRL_COOKIE = 9527
    FLAG_INVALID_LOADS = -1

    def __init__(self, *args, **kwargs):
        super(LinkLogger, self).__init__(*args, **kwargs)
        self.is_active = True
        self.host_map = {} # mac: endpoint, endpoint: mac
        self.link_map = {} # endpoint: endpoint
        self.shortest_route_map = {} # (src_dpid, dst_dpid): endpoint
        self.ctrllink_delay_map = {}
        self.datalink_delay_map = {}
        self.ctrllink_load_map = {}
        self.datalink_load_map = {}
        self.ctrllink_last_load = {}
        self.datalink_last_load = {}
        self.ctrllink_monitor = hub.spawn(self.ctrllink_monitor_routine)
        self.datalink_monitor = hub.spawn(self.datalink_monitor_routine)
        self.update_monitor = hub.spawn(self.update_monitor_routine)
        self.ctrllink_event = hub.Event()
        self.datalink_event = hub.Event()
        self.update_event = hub.Event()
        self.collector = hub.spawn(self.collector_routine)
    
    def add_flow(self, datapath, match, actions, priority, 
                 hard_timeout, idle_timeout, cookie, buffer_id):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, priority=priority,
                                        instructions=inst, cookie=cookie, buffer_id=buffer_id, 
                                        hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        else:
            mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, priority=priority,
                                        instructions=inst, cookie=cookie,
                                        hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def install_flow_rule(self, datapath, match=None, actions=None, priority=1, 
                          hard_timeout=0, idle_timeout=0, cookie=0, buffer_id=None):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # install table-miss flow entry
        if not match:
            match = ofp_parser.OFPMatch()
        if not actions:
            actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, priority, 
                      hard_timeout, idle_timeout, cookie, buffer_id)

    def install_table_miss(self, datapath):
        self.install_flow_rule(datapath, 
                               priority=0,
                               cookie=LinkLogger.MONITOR_CTRL_COOKIE)
        
    # add the probe rule whatever you like, if only it contains timestamp
    def install_probe_rule(self, datapath):
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(
            eth_type = ether_types.ETH_TYPE_IP,
            ipv4_dst = LinkLogger.MONITOR_PROBE_ADDRESS,
        )
        self.install_flow_rule(datapath, match=match)

    # used to stat the load of ctrl link 
    def send_flow_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath, 
                                             cookie=LinkLogger.MONITOR_CTRL_COOKIE)
        datapath.send_msg(req)
    
    # used to stat the load of data link
    def send_port_stats_request(self, datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, port_no=ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    # used to stat the delay of ctrl link
    def send_echo_request(self, datapath, data):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPEchoRequest(datapath, data)
        datapath.send_msg(req)
    
    def make_probe_packet(self):
        pkt = packet.Packet()
        ether_header = ethernet.ethernet(dst='00:00:DE:AD:FA:CE') # use default init params
        ip_header = ipv4.ipv4(dst=LinkLogger.MONITOR_PROBE_ADDRESS)
        pkt.add_protocol(ether_header)
        pkt.add_protocol(ip_header)
        pkt.add_protocol(struct.pack('!d', time.time()))
        pkt.serialize()
        return pkt.data
    
    def send_probe_request(self, datapath):
        # used to stat the delay of data link
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = self.make_probe_packet()
        out_msg = ofp_parser.OFPPacketOut(datapath=datapath, 
                                          actions=actions, 
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          data=data)
        datapath.send_msg(out_msg)
        
    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def flow_stats_reply_handler(self, ev):
    #     loads = 0
    #     datapath = ev.msg.datapath
    #     for stat in ev.msg.body:
    #         loads = self._update_ctrllink_last_loads(datapath.id, stat)
    #         break 
    #     if loads != LinkLogger.FLAG_INVALID_LOADS:
    #         self.update_ctrllink_loads(datapath.id, loads)
    #     #self.logger.info('dpid {} loads {} bytes/ms'.format(datapath.id, loads))
    

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        loads = 0
        datapath = ev.msg.datapath
        for stat in ev.msg.body:
            loads = self._update_datalink_history(datapath.id, stat)
            if loads != LinkLogger.FLAG_INVALID_LOADS:
                endpoint = (datapath.id, stat.port_no)
                self.update_datalink_loads(endpoint, loads)
            # self.logger.info('endpoints {}:{} loads {} bytes/ms'.format(
            #          datapath.id, stat.port_no, loads))
            
    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        recv_time = time.time()
        datapath = ev.msg.datapath
        (send_time, ) = struct.unpack('!d', ev.msg.data)
        ctrllink_delay = (recv_time - send_time) * 1000
        self.update_ctrllink_delay(datapath.id, ctrllink_delay)
        #self.logger.info('dpid {} delay {} ms'.format(datapath.id, ctrllink_delay))
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def probe_reply_handler(self, ev):
        recv_time = time.time()
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        _ip = pkt.get_protocol(ipv4.ipv4)
    
        if _ip and _ip.dst == LinkLogger.MONITOR_PROBE_ADDRESS:
            data = pkt.protocols[-1]
            send_time,  = struct.unpack('!d', data)
            datalink_delay = (recv_time - send_time) * 1000 
            dst_endpoint = (datapath.id, in_port)
            if dst_endpoint not in self.link_map:
                return 
            src_endpoint = self.link_map[dst_endpoint]
            self.update_datalink_delay(src_endpoint, datalink_delay)
    
    def _update_datalink_history(self, dpid, port_stat):
        endpoint = (dpid, port_stat.port_no)
        total_bytes = port_stat.tx_bytes
        total_times = port_stat.duration_sec + port_stat.duration_nsec / (10**9)
        if endpoint not in self.datalink_last_load:
            self.datalink_last_load[endpoint] = {
                'bytes': total_bytes,
                'times': total_times,
            }
            return LinkLogger.FLAG_INVALID_LOADS
        
        link_last_loads = self.datalink_last_load[endpoint]
        delta_bytes = total_bytes - link_last_loads['bytes']
        delta_times = total_times - link_last_loads['times']
        if delta_times == 0:
            return LinkLogger.FLAG_INVALID_LOADS, 0
        
        loads = delta_bytes / delta_times 
        link_last_loads['bytes'] = total_bytes
        link_last_loads['times'] = total_times
        return loads
    
    def update_ctrllink_delay(self, dpid, delay):
        if dpid not in self.ctrllink_delay_map:
            self.ctrllink_delay_map[dpid] = []
        elif len(self.ctrllink_delay_map[dpid]) >= LinkLogger.MONITOR_WINDOW_SIZE:
            self.ctrllink_delay_map[dpid].pop()
        self.ctrllink_delay_map[dpid].append(delay)

    def query_ctrllink_delay(self, dpid):
        if dpid in self.ctrllink_delay_map and \
            len(self.ctrllink_delay_map[dpid]) > 0:
            #return np.mean(self.ctrllink_delay_map[dpid])
            return self.ctrllink_delay_map[dpid][-1]
        return 0
            
    def update_datalink_loads(self, endpoint, loads):
        if endpoint not in self.datalink_load_map:
            self.datalink_load_map[endpoint] = []
        elif len(self.datalink_load_map[endpoint]) >= LinkLogger.MONITOR_WINDOW_SIZE:
            self.datalink_load_map[endpoint].pop()
        self.datalink_load_map[endpoint].append(loads)

    def query_datalink_loads(self, endpoint):
        if endpoint in self.datalink_load_map and \
            len(self.datalink_load_map[endpoint]) > 0:
                loads = self.datalink_load_map[endpoint][-1]
                if loads > 0:
                    return np.log(loads)
        return 0
    
    def update_datalink_delay(self, endpoint, delay):
        if endpoint not in self.datalink_delay_map:
            self.datalink_delay_map[endpoint] = []
        elif len(self.datalink_delay_map[endpoint]) >= LinkLogger.MONITOR_WINDOW_SIZE:
            self.datalink_delay_map[endpoint].pop()
        self.datalink_delay_map[endpoint].append(delay)
    
    def query_datalink_delay(self, endpoint):
        if endpoint in self.datalink_delay_map and \
            len(self.datalink_delay_map[endpoint]) > 0:
            #return np.mean(self.datalink_delay_map[endpoint])
            return self.datalink_delay_map[endpoint][-1]
        return 0
        
    def ctrllink_monitor_routine(self):
        while self.is_active:
            data = struct.pack('!d', time.time())
            switch_objs = get_all_switch(self)
            for switch_obj in switch_objs:
                datapath = switch_obj.dp
                self.send_echo_request(datapath, data)
            hub.sleep(LinkLogger.MONITOR_DELAY_IVAL/2)
            self.ctrllink_event.set()
            hub.sleep(LinkLogger.MONITOR_DELAY_IVAL/2)

    def datalink_monitor_routine(self):
        while self.is_active:
            switch_objs = get_all_switch(self)
            # update link state
            for switch_obj in switch_objs:
                datapath = switch_obj.dp
                self.send_probe_request(datapath)
                self.send_port_stats_request(datapath)
                link_state = get_link(self, datapath.id)
                for link_obj in link_state:
                    src_port_obj = link_obj.src
                    dst_port_obj = link_obj.dst
                    src_endpoint = (src_port_obj.dpid, src_port_obj.port_no)
                    dst_endpoint = (dst_port_obj.dpid, dst_port_obj.port_no)
                    self.link_map[src_endpoint] = dst_endpoint
            hub.sleep(LinkLogger.MONITOR_LOADS_IVAL/2)
            self.datalink_event.set()
            hub.sleep(LinkLogger.MONITOR_LOADS_IVAL/2)
    
    def collector_routine(self):
        logger_name = f'{int(time.time())}.txt'
        format_str = '{}:{} -> {}:{} {:.2f} {:.2f} {:.2f} {:.2f}\n'
        logger_times = 0
        while self.is_active:
            self.ctrllink_event.wait()
            self.datalink_event.wait()
            with open(logger_name, 'a+') as fp:
                for src_endpoint, dst_endpoint in self.link_map.items():
                    src_dpid, src_port_no = src_endpoint
                    dst_dpid, dst_port_no = dst_endpoint
                    src_ctrllink_delay = self.query_ctrllink_delay(src_dpid)
                    dst_ctrllink_delay = self.query_ctrllink_delay(dst_dpid)
                    datalink_delay = self.query_datalink_delay(src_endpoint)
                    datalink_loads = self.query_datalink_loads(src_endpoint)
                    log_item = format_str.format(
                        src_dpid, src_port_no, dst_dpid, dst_port_no,
                        src_ctrllink_delay, dst_ctrllink_delay,
                        datalink_delay, datalink_loads)
                    self.logger.info(log_item)
                    fp.write(log_item)
            if logger_times > 9005:
                sys.exit(0)
            else:
                logger_times += 1
            self.ctrllink_event.clear()
            self.datalink_event.clear()
    
    def _packet_in_forwarder(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ether_header = pkt.get_protocol(ethernet.ethernet)
        src, dst = ether_header.src, ether_header.dst
        dpid = datapath.id
        
        # validate src endpoint 
        src_endpoint = (dpid, in_port)
        if src_endpoint not in self.host_map:
            out_port = ofproto.OFPP_FLOOD
        elif src != self.host_map[src_endpoint]:
            return 
        
        # query dst endpoint
        if dst not in self.host_map:
            out_port = ofproto.OFPP_FLOOD
        else:
            dst_dpid, dst_port = self.host_map[dst]
            if dst_dpid == dpid:
                out_port = dst_port
            elif (dpid, dst_dpid) not in self.shortest_route_map:
                out_port = ofproto.OFPP_FLOOD
            else:
                dst_endpoint = self.shortest_route_map[(dpid, dst_dpid)]
                out_port = dst_endpoint[1] 
        
        actions = [ofp_parser.OFPActionOutput(out_port)]
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.install_flow_rule(datapath, match=match, actions=actions, 
                                       buffer_id=msg.buffer_id, hard_timeout=5)
                return
            else:
                self.install_flow_rule(datapath, match=match, 
                                       actions=actions, hard_timeout=5)
                
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None 
        out_msg = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out_msg) 

    def _packet_in_filter(self, pkt):
        ether_header = pkt.get_protocol(ethernet.ethernet)
        # filter non-eth packet
        if not ether_header: 
            return True 
        # filter lldp packet 
        if ether_header.ethertype == ether_types.ETH_TYPE_LLDP:
            return True 
        # filter ipv6 packet
        elif ether_header.ethertype == ether_types.ETH_TYPE_IPV6:
            return True 
        elif ether_header.ethertype == ether_types.ETH_TYPE_IP:
            ip_header = pkt.get_protocol(ipv4.ipv4)
            # filter probe packet 
            if ip_header.dst == LinkLogger.MONITOR_PROBE_ADDRESS:
                return True 
        return False 
    
    def update_monitor_routine(self):
        while self.is_active:
            self.update_event.wait()
            self.update_shortest_routes()
            self.update_event.clear()
            
    def _update_shortest_route(self, switch_objs, dpid):
        visited_map, visited_set = {}, {dpid}
        unvisited_set = {x.dp.id for x in switch_objs if x.dp.id != dpid}
        dpid_set = {k[0] for k in self.link_map.keys()}
        # Dijkstra: depth first traverse
        while len(visited_set) > 0:
            curr_dpid = visited_set.pop()
            if curr_dpid not in dpid_set:
                continue
            # k -> src_endpoint, v -> dst_endpoint
            current_link_map = {
                k: v for k, v in self.link_map.items() if k[0] == curr_dpid}
            for src_endpoint, dst_endpoint in current_link_map.items():
                src_dpid = src_endpoint[0]
                dst_dpid = dst_endpoint[0]         
                if dst_dpid in unvisited_set: 
                    if src_dpid not in visited_map:
                        visited_map[dst_dpid] = src_endpoint
                    else: 
                        visited_map[dst_dpid] = visited_map[src_dpid]
                    visited_set.add(dst_dpid)
            unvisited_set -= visited_set 
        for dst_dpid, endpoint in visited_map.items():
            self.shortest_route_map[(dpid, dst_dpid)] = endpoint

    def update_shortest_routes(self):
        switch_objs = get_all_switch(self)
        switch_ids = [x.dp.id for x in switch_objs]
        print('current switches: {}'.format(switch_ids))
        for dpid in switch_ids:
            # here we use shortest route, it should be changed then.
            self._update_shortest_route(switch_objs, dpid)
        self.logger.info('dynamic route map: {}'.format(self.shortest_route_map))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(ev.msg.data)
        if not self._packet_in_filter(pkt):
            self._packet_in_forwarder(ev)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.install_probe_rule(datapath)
        self.install_table_miss(datapath)
        
    @set_ev_cls(EventHostAdd)
    def host_add_handler(self, ev):
        host_obj = ev.host
        # host_obj.port is a Port object
        port_obj = host_obj.port
        dpid = port_obj.dpid
        port_no = port_obj.port_no 
        mac = host_obj.mac
        endpoint = (dpid, port_no)
        if endpoint not in self.host_map:
            self.host_map[mac] = endpoint 
            self.host_map[endpoint] = mac
            # self.logger.info('Add host {}: {}'.format(mac, endpoint)) 
        else:
            pass 
            # self.logger.info('Unknown host {}: {}'.format(mac, endpoint))

    # check link loop and re-calculate short path for switch to switch
    @set_ev_cls(EventLinkAdd)
    def link_add_handler(self, ev):
        link_obj = ev.link
        src_port, dst_port = link_obj.src, link_obj.dst
        src_endpoint = (src_port.dpid, src_port.port_no)
        dst_endpoint = (dst_port.dpid, dst_port.port_no)
        self.link_map[src_endpoint] = dst_endpoint
        self.link_map[dst_endpoint] = src_endpoint
        # NOTICE: this call should be delayed in case the request cannot 
        # be handled immediately.
        self.update_event.set()

    @set_ev_cls(EventLinkDelete)
    def link_del_handler(self, ev):
        link_obj = ev.link
        src_port, dst_port = link_obj.src, link_obj.dst
        src_endpoint = (src_port.dpid, src_port.port_no)
        dst_endpoint = (dst_port.dpid, dst_port.port_no)
        self.link_map.pop(src_endpoint, None)
        self.link_map.pop(dst_endpoint, None)
        self.update_event.set()
