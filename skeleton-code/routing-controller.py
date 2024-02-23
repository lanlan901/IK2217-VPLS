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
        BitField('tunnel_id', 0, 16),
        BitField('pw_id', 0, 16),
        BitField('ingress_port', 0, 16)]


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

        self.interface = params["interface"]

    def run(self):
        sniff(iface=self.cpu_port_intf, prn=self.recv_msg_cpu)

    def recv_msg_cpu(self, pkt):
        print("received packet at " + str(self.sw_name) + " controller")

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header = CpuHeader(packet.payload)
            # todo
            self.process_packet([(cpu_header.srcAddr, cpu_header.tunnel_id, cpu_header.pw_id, cpu_header.ingress_port)])
        elif packet.type == 0x5678:
            rtt_header = RttHeader(packet.payload)
            self.process_packet_rtt(
                [(rtt_header.customer_id, rtt_header.ip_addr_src, rtt_header.ip_addr_dst, rtt_header.rtt)])

    def process_packet(self, packet_data):
        ### use exercise 04-Learning as a reference point
        for macAddr, ingress_port in packet_data:
            self.controller.table_add('learning_table', 'mac_learn', [str(macAddr)], [])
            self.controller.table_add('forward_table', 'forward', [str(macAddr)], [str(ingress_port)])
            return
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
        self.pe_pairs = [] #按照相同角标存储两个pe 角标是id
        self.pe_list = []
        self.non_pe_list = []

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

    def generate_tunnel_list(self): ##返回经过所有交换机的隧道列表
        pe = []
        tunnel_dict = {}
        tunnel_path_list = []
        for sw_name in self.topo.get_p4switches().keys():
            if len(self.topo.get_hosts_connected_to(sw_name)) != 0:
                pe.append(sw_name)
        pe_pairs = list(itertools.combinations(pe, 2))
        for sw_pair in pe_pairs:
            paths = self.topo.get_shortest_paths_between_nodes(sw_pair[0], sw_pair[1])
            tunnel_dict[tuple(sorted(sw_pair))] = paths
            #for path in paths:
            tunnel_path_list.append(paths)
        self.tunnel_path_list = tunnel_path_list
        self.tunnel_dict = tunnel_dict
        self.pe_pairs = pe_pairs

    def get_pw_id(self, sw_name, host_name): #连接到特定交换机的特定主机和pw_id的映射
        port_num = self.topo.node_to_node_port_num(sw_name, host_name)
        customer_label = self.vpls_conf['hosts'][host_name]
        pw_id = hash(customer_label) %1024 + port_num
        return pw_id
    
    def get_pe_list(self):
        for sw_name in self.topo.get_p4switches().keys():
            if len(self.topo.get_hosts_connected_to(sw_name)) > 0 :
                self.pe_list.append(sw_name)
            elif len(self.topo.get_hosts_connected_to(sw_name)) == 0 :
                self.non_pe_list.append(sw_name)

    def get_tunnel_ports(self, tunnel, sw_name): ##单个隧道中交换机的端口号
        ports = []
        if tunnel.index(sw_name) == 0:#起点
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[1]))
        elif tunnel.index(sw_name) == len(tunnel) - 1:#终点
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[len(tunnel) - 2]))
        else:#中间
            index = tunnel.index(sw_name)
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[index - 1]))
            ports.append(self.topo.node_to_node_port_num(sw_name, tunnel[index + 1]))
        return ports
    
    def sw_to_tunnel_ports(self, sw_name): ##交换机到隧道端口
        ports = []
        for tunnel in self.tunnel_path_list:
            if sw_name in tunnel:
                port_num = self.get_tunnel_ports(tunnel, sw_name)
                for port in port_num:
                    if not port in port_num:
                        ports.append(port)
        return ports
    
    def sw_to_host_ports(self, sw_name): ##交换机到主机端口
        ports = []
        for host in self.get_hosts_connected_to(sw_name):
            port_num = self.node_to_node_port_num(sw_name, host)
            for port in port_num:
                if not port in port_num:
                    ports.append(port)
        return ports

    def port_to_tunnel(self, sw_name, port): ##端口号参与的隧道列表
        tunnels = []
        for tunnel in self.tunnel_list:
            if sw_name in tunnel:
                if port in self.get_tunnel_ports(tunnel,sw_name):
                    tunnels.append(tunnel)
        return tunnels
                
    def process_network(self):
        mc_grp_id = 1

        self.generate_tunnel_list()
        self.get_pe_list()

        for pe_pair in self.pe_pairs:
            pe1 = pe_pair[0]
            pe2 = pe_pair[1]
            tunnel_id = self.pe_pairs.index(pe_pair)

            paths =  self.tunnel_path_list[tunnel_id]

            if len(paths) == 1:#如果这个隧道只有一条路径
                path = paths[0]

                #设置pe1 pe2的表
                ex_sw1 = path[path.index(pe1) + 1]
                sw_port1 = self.topo.node_to_node_port_num(pe1, ex_sw1)#与pe1相邻的sw的端口
                ex_sw2 = path[path.index(pe2) - 1]
                sw_port2 = self.topo.node_to_node_port_num(pe2, ex_sw2)#与pe2相邻的sw的端口
                sw1_mac = self.topo.node_to_node_mac(ex_sw1, pe1)
                sw2_mac = self.topo.node_to_node_mac(ex_sw2, pe2)
                for host1 in self.topo.get_hosts_connected_to(pe1):
                    for host2 in self.topo.get_hosts_connected_to(pe2):
                        host_port1 = self.topo.node_to_node_port_num(pe1, host1)#与pe1相邻的host的端口
                        host_port2 = self.topo.node_to_node_port_num(pe2, host2)#与pe2相邻的host的端口
                        host1_mac = self.topo.get_host_mac(host1)
                        host2_mac = self.topo.get_host_mac(host2)
                        pw_id1 = self.get_pw_id(pe1, host1)
                        pw_id2 = self.get_pw_id(pe2, host2)
                        #设置已封装包的转发
                        self.controllers[pe1].table_add("tunnel_ecmp", "set_nhop", [str(host_port1), str(tunnel_id)], [str(sw_port1)])
                        self.controllers[pe2].table_add("tunnel_ecmp", "set_nhop", [str(host_port2), str(tunnel_id)], [str(sw_port2)])
                        #设置封装包
                        self.controllers[pe1].table_add("whether_encap", "encap", [str(host_port1), str(host1_mac), str(host2_mac)], 
                                                        [str(tunnel_id), str(pw_id2)])
                        self.controllers[pe2].table_add("whether_encap", "encap", [str(host_port2), str(host2_mac), str(host1_mac)], 
                                                        [str(tunnel_id), str(pw_id1)])
                        #设置解封包
                        self.controllers[pe1].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port1), str(pw_id1)], [str(host_port1)])
                        self.controllers[pe2].table_add("whether_decap_nhop", "decap_nhop", [str(sw_port2), str(pw_id2)], [str(host_port2)])

                for sw in path[1:-1]:#todo  设置路径中间的节点的表
                    sw1 = path[path.index(sw) - 1]
                    sw2 = path[path.index(sw) + 1]
                    sw_port1 = self.topo.node_to_node_port_num(sw, sw1)#与pe1相邻的sw的端口
                    sw_port2 = self.topo.node_to_node_port_num(sw, sw2)#与pe2相邻的sw的端口
                    self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port1), str(tunnel_id)], [str(sw_port2)])
                    self.controllers[sw].table_add("tunnel_ecmp", "set_nhop", [str(sw_port2), str(tunnel_id)], [str(sw_port1)])


            else:#todo ecmp 
        
                    
          

        
        ## muilticast: 1. 获取PE到隧道端口的映射 2. 获取PE到主机端口的映射 3. 非PE直接forward packet
        #    for pe_to_tunnel_ports in self.sw_to_tunnel_ports(pe):
        #       for tunnel in self.port_to_tunnel(pe, pe_to_tunnel_ports):
        #            tunnel_id = self.tunnel_list.index(tunnel) + 1
        #            self.controller.mc_mgrp_create(mc_grp_id)
        #            tunnel_port_list = []
        #            tunnel_port_list.append(pe_to_tunnel_ports)
        #            handle = self.controllers[pe].mc_node_create(tunnel_id, tunnel_port_list) ##为PE参与的每个隧道创建一个多播组
        #            self.controllers[pe].mc_node_associate(mc_grp_id, handle)
        #            mc_grp_id += 1

        for pe in self.pe_list:

            for pe_pair in self.pe_pairs:
                tunnel_port_list = self.sw_to_tunnel_ports(pe)
                pe1 = pe_pair[0]
                pe2 = pe_pair[1]
                tunnel_id = self.pe_pairs.index(pe_pair)
                self.controllers[pe].mc_mgrp_create(mc_grp_id)
                handle = self.controllers[pe].mc_node_create(tunnel_id, tunnel_port_list)
                self.controllers[pe].mc_node_associate(mc_grp_id, handle)
                for tunnel_port in tunnel_port_list:
                    self.controllers[pe].table_add('select_mcast_grp','set_mcast_grp', [str(tunnel_port)], [str(mc_grp_id)])
                mc_grp_id += 1      

            for host in self.topo.get_hosts_connected_to(pe):
                host_port_list = self.sw_to_host_ports(pe)
                pw_id = self.get_pw_id(pe, host)
                self.controllers[pe].mc_mgrp_create(mc_grp_id)
                handle = self.controllers[pe].mc_node_create(pw_id, host_port_list) ##pw_id和主机端口列表的多播句柄
                self.controllers[pe].mc_node_associate(mc_grp_id, handle)
                for host_port in host_port_list:
                    self.controllers[pe].table_add('select_mcast_grp','set_mcast_grp', [str(host_port)], [str(mc_grp_id)])
                mc_grp_id += 1






        for non_pe in self.non_pe_list:
            tunnel_list_non_pe = []
            tunnel_id_list_non_pe = []
            for tunnel in self.tunnel_path_list:
                if non_pe in tunnel:
                    tunnel_list_non_pe.append(tunnel)
                    tunnel_id_list_non_pe.append(tunnel_id)##todo

            for index in range(len(tunnel_list_non_pe)):
                tunnel = tunnel_list_non_pe[index]
                tunnel_id = tunnel_id_list_non_pe[index]
                ports = self.get_tunnel_ports(tunnel, non_pe)
                ##forward
                self.controllers[non_pe].table_add('tunnel_forward_table', 'forward', [str(ports[0]), str(tunnel_id)], [str(ports[1])])
                self.controllers[non_pe].table_add('tunnel_forward_table', 'forward', [str(ports[1]), str(tunnel_id)], [str(ports[0])])


        


        ### logic to be executed at the start-up of the topology
        ### hint: compute ECMP paths here
        ### use exercise 08-Simple Routing as a reference
        pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Error: vpls.conf file missing")
        sys.exit()
    vpls_conf_file = sys.argv[1]
    controller = RoutingController(vpls_conf_file)
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
        params["interface"] = controller
        thread = EventBasedController(params)
        thread.setName('MyThread ' + str(sw_name))
        thread.daemon = True
        thread_list.append(thread)
        thread.start()
    for thread in thread_list:
        thread.join()
    print("Thread has finished")
