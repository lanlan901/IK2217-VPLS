# -*- coding: utf-8 -*-



from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from multiprocessing import Pool
import itertools
import threading
import json
import ipaddress

from scapy.fields import IPField


class CpuHeader(Packet):
    name = 'CpuPacket'
    ### define your own CPU header
    fields_desc = [
        BitField('srcAddr', 0, 48),
        BitField('ingress_port', 0, 16),
        BitField('tunnel_id', 0, 16),
        BitField('dst_pw_id', 0, 16),
        BitField('src_pw_id', 0, 16)
        ]


class RttHeader(Packet):
    name = 'RttPacket'
    fields_desc = [
        BitField('customer_id', 0, 16),
        BitField('ip_addr_src', 0, 32),
        BitField('ip_addr_dst', 0, 32),
        BitField('rtt', 0, 48)]


class EventBasedController(threading.Thread):
    def __init__(self, params):
        super(EventBasedController, self).__init__()
        self.topo = Topology(db="topology.db")
        self.sw_name = params["sw_name"]
        self.cpu_port_intf = params["cpu_port_intf"]
        self.thrift_port = params["thrift_port"]
        self.id_to_switch = params["id_to_switch"]
        self.controller = SimpleSwitchAPI(thrift_port)
        self.vpls_conf_file = params["vpls_conf_file"]
        self.init()

    def init(self):
        self.extract_customers_information()
        
    def extract_customers_information(self):
        with open(self.vpls_conf_file) as json_file:
            self.vpls_conf = json.load(json_file)
            
    def get_pw_id(self, sw_name, host_name): #mapping between host and pw_id, given switch  连接到特定交换机的特定主机和pw_id的映射

        port_num = self.topo.node_to_node_port_num(sw_name, host_name)
        customer_label = self.vpls_conf['hosts'][host_name]
        pw_id = hash(customer_label + sw_name) %1024 + port_num
        return pw_id
    
    def int_to_mac(self, int_value):
        mac = ':'.join(('%012X' % int_value)[i:i+2] for i in range(0, 12, 2))
        return mac

    def run(self):
        sniff(iface=self.cpu_port_intf, prn=self.recv_msg_cpu)

    def recv_msg_cpu(self, pkt):
        print("received packet at " + str(self.sw_name))

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header = CpuHeader(packet.payload)
            # todo
            
            self.process_packet([(cpu_header.srcAddr, cpu_header.ingress_port, cpu_header.tunnel_id, cpu_header.src_pw_id, cpu_header.dst_pw_id)])
        elif packet.type == 0x5678:
            rtt_header = RttHeader(packet.payload)
            self.process_packet_rtt(
                [(rtt_header.customer_id, rtt_header.ip_addr_src, rtt_header.ip_addr_dst, rtt_header.rtt)])

    def process_packet(self, packet_data):
        for macAddr, ingress_port, tunnel_id, src_pw_id, dst_pw_id in packet_data:
            ##learn MAC address
            mac_str = self.int_to_mac(macAddr)
            
            print("tunnel_id: {} src_pw_id :{} dst_pw_id :{}".format(tunnel_id, src_pw_id, dst_pw_id))
            
            if src_pw_id != 0 and dst_pw_id != 0:
                print("true1")
                for host in self.topo.get_hosts_connected_to(self.sw_name):
                    pw_id = self.get_pw_id(self.sw_name, host)
                    if pw_id == dst_pw_id:
                        print("true2")
                        host_port = self.topo.node_to_node_port_num(self.sw_name, host)
                        host_mac = self.topo.get_host_mac(host)
                        self.controller.table_add("whether_encap", "encap", [str(host_port), str(host_mac), str(macAddr)], 
                                                    [str(tunnel_id), str(pw_id), str(src_pw_id)])
                        print("on {}: Adding to whether_encap with action encap: keys = [{}, {}, {}], values = [{}, {}, {}]".format
                                                    (self.sw_name, host_port, host_mac, mac_str, tunnel_id, pw_id, src_pw_id))
            
            self.controller.table_add('learning_table', 'NoAction', [str(macAddr), str(src_pw_id)], [])
            print("on {}: Adding to learning_table with NoAction: keys = [{}, {}], values = []".format
                                (self.sw_name, mac_str, src_pw_id))
        pass
    
    def process_packet_rtt(self, packet_data):
        for customer_id, ip_addr_src, ip_addr_dst, rtt in packet_data:
            print("Customer_id: " + str(customer_id))
            print("SourceIP: " + str(ipaddress.IPv4Address(ip_addr_src)))
            print("DestinationIP: " + str(ipaddress.IPv4Address(ip_addr_dst)))
            print("RTT: " + str(rtt))


class RoutingController(object):

    def __init__(self, vpls_conf_file):
        self.topo = Topology(db="topology.db")
        self.cpu_ports = {x: self.topo.get_cpu_port_index(x) for x in self.topo.get_p4switches().keys()}
        self.controllers = {}
        self.vpls_conf_file = vpls_conf_file
        self.init()
        self.tunnel_path_list = []
        self.pe_pairs = []
        self.pe_list = []
        self.non_pe_list = []
        # self.whether_single = False
        self.host_list =[]
        self.path_list_temp = []

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.add_mirror()
        self.extract_customers_information()
        self.switch_to_id = {sw_name: self.get_switch_id(sw_name) for sw_name in self.topo.get_p4switches().keys()}
        self.id_to_switch = {self.get_switch_id(sw_name): sw_name for sw_name in self.topo.get_p4switches().keys()}

    def add_mirror(self):
        for sw_name in self.topo.get_p4switches().keys():
            self.controllers[sw_name].mirroring_add(100, self.cpu_ports[sw_name])

    def extract_customers_information(self):
        with open(self.vpls_conf_file) as json_file:
            self.vpls_conf = json.load(json_file)

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def get_switch_id(self, sw_name):
        return "{:02x}".format(self.topo.get_p4switches()[sw_name]["sw_id"])

    def generate_tunnel_list(self): ##genernate all the pe_pairs and tunnel paths  返回经过所有交换机的隧道列表

        pe = []
        tunnel_path_list = []
        for sw_name in self.topo.get_p4switches().keys():
            if len(self.topo.get_hosts_connected_to(sw_name)) != 0:
                pe.append(sw_name)
                print("pe:{}".format(pe))
        pe_pairs = list(itertools.combinations(pe, 2))
        for sw_pair in pe_pairs:
            paths = self.topo.get_shortest_paths_between_nodes(sw_pair[0], sw_pair[1])
            for path in paths:
                if 'sw-cpu' in path:
                    paths.remove(path)
            tunnel_path_list.append(paths)
        self.tunnel_path_list = tunnel_path_list
        self.pe_pairs = pe_pairs
        print("pe_pairs: {}".format(pe_pairs))
        print("tunnel_path_list: {}".format(tunnel_path_list))

    def get_pw_id(self, sw_name, host_name): #mapping between host and pw_id, given switch  连接到特定交换机的特定主机和pw_id的映射

        port_num = self.topo.node_to_node_port_num(sw_name, host_name)
        customer_label = self.vpls_conf['hosts'][host_name]
        pw_id = hash(customer_label + sw_name) %1024 + port_num
        return pw_id
    
    def get_pe_list(self):
        for sw_name in self.topo.get_p4switches().keys():
            if len(self.topo.get_hosts_connected_to(sw_name)) > 0 :
                self.pe_list.append(sw_name)
            elif len(self.topo.get_hosts_connected_to(sw_name)) == 0 :
                self.non_pe_list.append(sw_name)

    def sw_to_tunnel_ports(self, sw_name): ##given switch, get the ports connected to tunnel
        port_set = set()
        for tunnel_paths in self.tunnel_path_list:
            for tunnel in tunnel_paths:
                if sw_name in tunnel:
                    port_set.update(self.get_tunnel_ports(tunnel, sw_name))
        ports = list(port_set)
        print("for sw{} to tunnel ports:{}".format(sw_name, ports))
        return ports
    
    def get_tunnel_ports(self, tunnel, sw_name):
        ports = []
        if tunnel.index(sw_name) == 0:#start
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[1]))
        elif tunnel.index(sw_name) == len(tunnel) - 1:#end
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[len(tunnel) - 2]))
        else:#middle
            index = tunnel.index(sw_name)
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[index - 1]))
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[index + 1]))
        return ports

    def sw_to_host_ports(self, sw_name): ##given switch, get the ports connected to hosts
        ports = []
        host_list = self.topo.get_hosts_connected_to(sw_name)
        for host in host_list:
            port = self.topo.node_to_node_port_num(sw_name, host)
            ports.append(port)
        return ports
    
    def get_host_list(self): ##get all the hosts
        host_list = []
        for pe in self.pe_list:
            hosts_pe = self.topo.get_hosts_connected_to(pe)
            host_list = host_list + hosts_pe
            
        self.host_list = host_list
        return host_list

    def process_network(self):

        self.generate_tunnel_list()
        self.get_pe_list()
        ecmp_group_id = 0
        mc_grp_id = 1
        

        for pe in self.pe_list: #for directly forward situation (topo 1 or h5-h6 in topo6)
            hosts = self.topo.get_hosts_connected_to(pe)
            host_pairs = list(itertools.combinations(hosts, 2))

            for host_pair in host_pairs:
                host1 = host_pair[0]
                host2 = host_pair[1]
                customer1_id = self.vpls_conf['hosts'][host1]
                customer2_id = self.vpls_conf['hosts'][host2]

                if(customer1_id != customer2_id):
                    continue
                host1_port = self.topo.node_to_node_port_num(pe, host1)
                host1_mac = self.topo.get_host_mac(host1)
                host2_port = self.topo.node_to_node_port_num(pe, host2)
                host2_mac = self.topo.get_host_mac(host2)

                self.controllers[pe].table_add("forward_table", "forward", [str(host1_port), str(host2_mac)], [str(host2_port)])
                self.controllers[pe].table_add("forward_table", "forward", [str(host2_port), str(host1_mac)], [str(host1_port)])
                
                
                print("on {}: Adding to forward_table with action forward: keys = [{}, {}], values = [{}]".format(pe, host1_port, host2_mac, host2_port))
                print("on {}: Adding to forward_table with action forward: keys = [{}, {}], values = [{}]".format(pe, host2_port, host1_mac, host1_port))
        

        #ecmp
        for pe_pair in self.pe_pairs:
            print("generate_pe_pairs")
            pe1 = pe_pair[0]
            pe2 = pe_pair[1]
            tunnel_id = self.pe_pairs.index(pe_pair)
        
            paths =  self.tunnel_path_list[tunnel_id]
            
            if len(paths) == 1:#only one path for the tunnel
                path = paths[0]

                #设置pe1 pe2的表
                ex_sw1 = path[path.index(pe1) + 1]
                sw_port1 = self.topo.node_to_node_port_num(pe1, ex_sw1)#port between pe1 and sw
                ex_sw2 = path[path.index(pe2) - 1]
                sw_port2 = self.topo.node_to_node_port_num(pe2, ex_sw2)
                sw1_mac = self.topo.node_to_node_mac(ex_sw1, pe1)
                sw2_mac = self.topo.node_to_node_mac(ex_sw2, pe2)
                for host1 in self.topo.get_hosts_connected_to(pe1):
                    for host2 in self.topo.get_hosts_connected_to(pe2):
                        print("dual host loop")
                        customer1_id = self.vpls_conf['hosts'][host1]
                        customer2_id = self.vpls_conf['hosts'][host2]
                        if(customer1_id != customer2_id):
                            continue
                        host_port1 = self.topo.node_to_node_port_num(pe1, host1)#port between pe1 and host1
                        host_port2 = self.topo.node_to_node_port_num(pe2, host2)

                        host1_mac = self.topo.get_host_mac(host1)
                        host2_mac = self.topo.get_host_mac(host2)

                        pw_id1 = self.get_pw_id(pe1, host1)
                        pw_id2 = self.get_pw_id(pe2, host2)

                        #forward the encapsulated packet #设置已封装包的转发
                        self.controllers[pe1].table_add("tunnel_ecmp", "set_nhop", [str(host_port1), str(tunnel_id)], [str(sw_port1)])
                        self.controllers[pe2].table_add("tunnel_ecmp", "set_nhop", [str(host_port2), str(tunnel_id)], [str(sw_port2)])

                        #check whether needs encapsulation or not #设置封装包
                        # self.controllers[pe1].table_add("whether_encap", "encap", [str(host_port1), str(host1_mac), str(host2_mac)], 
                        #                                 [str(tunnel_id), str(pw_id2)])
                        # self.controllers[pe2].table_add("whether_encap", "encap", [str(host_port2), str(host2_mac), str(host1_mac)], 
                        #                                 [str(tunnel_id), str(pw_id1)])
                        #check whether it can be decapsulated and forward #设置解封包
                        self.controllers[pe1].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port1), str(pw_id1)], [str(host_port1)])
                        self.controllers[pe2].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port2), str(pw_id2)], [str(host_port2)])

                        print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(pe1, host_port1, tunnel_id, sw_port1))
                        print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(pe2, host_port2, tunnel_id, sw_port2))

                        # print("on {}: Adding to whether_encap with action encap: keys = [{}, {}, {}], values = [{}, {}]".format(pe1, host_port1, host1_mac, host2_mac, tunnel_id, pw_id2))
                        # print("on {}: Adding to whether_encap with action encap: keys = [{}, {}, {}], values = [{}, {}]".format(pe2, host_port2, host2_mac, host1_mac, tunnel_id, pw_id1))

                        print("on {}: Adding to whether_decap_nhop with action decap_nhop: keys = [{}, {}], values = [{}]".format(pe1, sw_port1, pw_id1, host_port1))
                        print("on {}: Adding to whether_decap_nhop with action decap_nhop: keys = [{}, {}], values = [{}]".format(pe2, sw_port2, pw_id2, host_port2))

                ## for switches in the middle of the path
                #设置路径中间的节点的表
                for sw in path[1:-1]:
                    sw1 = path[path.index(sw) - 1]
                    sw2 = path[path.index(sw) + 1]
                    sw_port1 = self.topo.node_to_node_port_num(sw, sw1)
                    sw_port2 = self.topo.node_to_node_port_num(sw, sw2)
                    self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port1), str(tunnel_id)], [str(sw_port2)])
                    self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port2), str(tunnel_id)], [str(sw_port1)])

                    print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(sw, sw_port1, tunnel_id, sw_port2))
                    print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(sw, sw_port2, tunnel_id, sw_port1))


            else:## multiple paths 多条路径
                sw1_ports = []
                sw2_ports = []
                for path in paths:
                    ex_sw1 = path[path.index(pe1) + 1]
                    sw_port1 = self.topo.node_to_node_port_num(pe1, ex_sw1)
                    sw1_ports.append(sw_port1)
                    ex_sw2 = path[path.index(pe2) - 1]
                    sw_port2 = self.topo.node_to_node_port_num(pe2, ex_sw2)
                    sw2_ports.append(sw_port2)

                    for sw in path[1:-1]:#设置路径中间的节点的表
                        sw1 = path[path.index(sw) - 1]
                        sw2 = path[path.index(sw) + 1]
                        sw_port1 = self.topo.node_to_node_port_num(sw, sw1)#与pe1相邻的sw的端口
                        sw_port2 = self.topo.node_to_node_port_num(sw, sw2)#与pe2相邻的sw的端口
                        self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port1), str(tunnel_id)], [str(sw_port2)])
                        self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port2), str(tunnel_id)], [str(sw_port1)])
                        print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(sw, sw_port1, tunnel_id, sw_port2))
                        print("on {}: Adding to tunnel_ecmp with action set_nhop: keys = [{}, {}], values = [{}]".format(sw, sw_port2, tunnel_id, sw_port1))


                #此tunnel中给pe1分配的groupid
                ecmp_group_id1 = ecmp_group_id
                ecmp_group_id2 = ecmp_group_id + 1
                ecmp_group_id = ecmp_group_id + 2

                #set ecmp group to next hop
                for i in range(len(sw1_ports)):
                    self.controllers[pe1].table_add("ecmp_group_to_nhop", "set_nhop", [str(ecmp_group_id1), str(i)], [str(sw1_ports[i])])
                    self.controllers[pe2].table_add("ecmp_group_to_nhop", "set_nhop", [str(ecmp_group_id2), str(i)], [str(sw2_ports[i])])

                    print("on {}: Adding to ecmp_group_to_nhop with action set_nhop: keys = [{}, {}], values = [{}]".format(pe1, ecmp_group_id1, i, sw1_ports[i]))
                    print("on {}: Adding to ecmp_group_to_nhop with action set_nhop: keys = [{}, {}], values = [{}]".format(pe2, ecmp_group_id2, i, sw2_ports[i]))

                for path in paths:
                    ex_sw1 = path[path.index(pe1) + 1]
                    sw_port1 = self.topo.node_to_node_port_num(pe1, ex_sw1)#与pe1相邻的sw的端口
                    ex_sw2 = path[path.index(pe2) - 1]
                    sw_port2 = self.topo.node_to_node_port_num(pe2, ex_sw2)#与pe2相邻的sw的端口
                    
                    #todo
                    for host1 in self.topo.get_hosts_connected_to(pe1):
                        for host2 in self.topo.get_hosts_connected_to(pe2):
                            customer1_id = self.vpls_conf['hosts'][host1]
                            customer2_id = self.vpls_conf['hosts'][host2]
                            if(customer1_id != customer2_id):
                                continue
                            host_port1 = self.topo.node_to_node_port_num(pe1, host1)#与pe1相邻的host的端口
                            host_port2 = self.topo.node_to_node_port_num(pe2, host2)#与pe2相邻的host的端口
                            host1_mac = self.topo.get_host_mac(host1)
                            host2_mac = self.topo.get_host_mac(host2)
                            pw_id1 = self.get_pw_id(pe1, host1)
                            pw_id2 = self.get_pw_id(pe2, host2)

                            #forward the encapsulated packet
                            self.controllers[pe1].table_add("tunnel_ecmp", "ecmp_group", 
                                                            [str(host_port1), str(tunnel_id)], [str(ecmp_group_id1), str(len(sw1_ports))])
                            self.controllers[pe2].table_add("tunnel_ecmp", "ecmp_group", 
                                                            [str(host_port2), str(tunnel_id)], [str(ecmp_group_id2), str(len(sw2_ports))])
                            #check whether needs encapsulation or not
                            #todo
                            # self.controllers[pe1].table_add("whether_encap", "encap", [str(host_port1), str(host1_mac), str(host2_mac)], 
                            #                             [str(tunnel_id), str(pw_id2)])
                            # self.controllers[pe2].table_add("whether_encap", "encap", [str(host_port2), str(host2_mac), str(host1_mac)], 
                            #                             [str(tunnel_id), str(pw_id1)])
                            #check whether it can be decapsulated and forward
                            self.controllers[pe1].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port1), str(pw_id1)], [str(host_port1)])
                            self.controllers[pe2].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port2), str(pw_id2)], [str(host_port2)])

                            print("on {}: Adding to tunnel_ecmp with action ecmp_group: keys = [{}, {}], values = [{}, {}]".format(pe1, host_port1, tunnel_id, ecmp_group_id1, len(sw1_ports)))
                            print("on {}: Adding to tunnel_ecmp with action ecmp_group: keys = [{}, {}], values = [{}, {}]".format(pe2, host_port2, tunnel_id, ecmp_group_id2, len(sw2_ports)))

                            # print("on {}: Adding to whether_encap with action encap: keys = [{}, {}, {}], values = [{}, {}]".format(pe1, host_port1, host1_mac, host2_mac, tunnel_id, pw_id2))
                            # print("on {}: Adding to whether_encap with action encap: keys = [{}, {}, {}], values = [{}, {}]".format(pe2, host_port2, host2_mac, host1_mac, tunnel_id, pw_id1))

                            print("on {}: Adding to whether_decap_nhop with action decap_nhop: keys = [{}, {}], values = [{}]".format(pe1, sw_port1, pw_id1, host_port1))
                            print("on {}: Adding to whether_decap_nhop with action decap_nhop: keys = [{}, {}], values = [{}]".format(pe2, sw_port2, pw_id2, host_port2))


        ## muilticast
        for pe in self.pe_list:        
            A_port_list = []
            B_port_list = []

            tunnel_port_list = self.sw_to_tunnel_ports(pe)

            for host in self.topo.get_hosts_connected_to(pe): 
                customer_id = self.vpls_conf['hosts'][host]
                port_num = self.topo.node_to_node_port_num(pe, host)
                if customer_id == 'A':
                    A_port_list.append(port_num)
                if customer_id == 'B':
                    B_port_list.append(port_num)

            print("for pe:{} A_port_list:{}".format(pe, A_port_list))
            print("for pe:{} B_list_list:{}".format(pe, B_port_list))

            rid = 1
            for host in self.topo.get_hosts_connected_to(pe): 
                customer_id = self.vpls_conf['hosts'][host]
                port_num = self.topo.node_to_node_port_num(pe, host)
                ports_list_temp = []
                handle_host = None

                #handle for switch to hosts 主机节点
                if customer_id == 'A':
                    ports_list_temp = A_port_list[:]
                    ports_list_temp.remove(port_num)
                    handle_host = self.controllers[pe].mc_node_create(0, ports_list_temp)
                    print("handle_host:")
                    print(ports_list_temp)

                if customer_id == 'B':
                    ports_list_temp = B_port_list[:]
                    ports_list_temp.remove(port_num)
                    handle_host = self.controllers[pe].mc_node_create(0, ports_list_temp)
                    print("handle_host:")
                    print(ports_list_temp)
                
                
                all_host_list = self.get_host_list()
                pe_host_list = self.topo.get_hosts_connected_to(pe)
                # hosts except for current host 除了当前主机以外的主机列表
                expe_host_list = [item for item in all_host_list if item not in pe_host_list] 
                tunnel_ids = []
                pw_ids = []
                my_pw_id = self.get_pw_id(pe, host)

                for host1 in expe_host_list:#遍历其他主机  get tunnel id  pwid
                    if self.vpls_conf['hosts'][host] == self.vpls_conf['hosts'][host1]:#if the customer label is the same 
                        for pe_pair in self.pe_pairs:
                            if(pe_pair[0] == pe):
                                if host1 in self.topo.get_hosts_connected_to(pe_pair[1]):
                                    tunnel_ids.append(self.pe_pairs.index(pe_pair))
                                    pw_ids.append(self.get_pw_id(pe_pair[1], host1))
                                    
                            elif(pe_pair[1] == pe):
                                if host1 in self.topo.get_hosts_connected_to(pe_pair[0]):
                                    tunnel_ids.append(self.pe_pairs.index(pe_pair))
                                    pw_ids.append(self.get_pw_id(pe_pair[0], host1))
                
                #handles list for switch to tunnels 隧道节点
                handle_tunnels = []
                for index in range(len(tunnel_ids)):
                    print("handle_tunnel:")
                    print(tunnel_port_list)
                    handle_tunnel = self.controllers[pe].mc_node_create(rid, tunnel_port_list)
                    handle_tunnels.append(handle_tunnel)
                    self.controllers[pe].table_add('whether_encap_egress', 'encap_egress', [str(rid)], [str(tunnel_ids[index]), str(my_pw_id), str(pw_ids[index])])
                    print("on {}: Adding to whether_encap_egress with action encap_egress: keys = [{}], values = [{}, {}]".format(pe, rid, tunnel_ids[index], pw_ids[index]))
                    rid = rid + 1    
            
                self.controllers[pe].mc_mgrp_create(mc_grp_id)
                self.controllers[pe].mc_node_associate(mc_grp_id, handle_host)
                for handle_tunnel in handle_tunnels:
                    self.controllers[pe].mc_node_associate(mc_grp_id, handle_tunnel)
                self.controllers[pe].table_add('select_mcast_grp', 'set_mcast_grp', [str(port_num)], [str(mc_grp_id)])
                print("handle_tunnel and handle_host ass to mgrp: {}".format(mc_grp_id))
                print("on {}: Adding to select_mcast_grp with action set_mcast_grp: keys = [{}], values = [{}]".format(pe, port_num, mc_grp_id))

                # one multicast group id for each host
                mc_grp_id += 1
        pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Error: vpls.conf file missing")
        sys.exit()
    vpls_conf_file = sys.argv[1]
    controller = RoutingController(vpls_conf_file)
    print("process start")
    controller.process_network()
    thread_list = []
    for sw_name in controller.topo.get_p4switches().keys():
        cpu_port_intf = str(controller.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1"))
        thrift_port = controller.topo.get_thrift_port(sw_name)
        id_to_switch = controller.id_to_switch
        params = {}
        params["sw_name"] = sw_name
        params["cpu_port_intf"] = cpu_port_intf
        params["thrift_port"] = thrift_port
        params["id_to_switch"] = id_to_switch
        params["vpls_conf_file"] = vpls_conf_file
        thread = EventBasedController(params)
        thread.setName('MyThread ' + str(sw_name))
        thread.daemon = True
        thread_list.append(thread)
        thread.start()
    for thread in thread_list:
        thread.join()
    print("Thread has finished")
