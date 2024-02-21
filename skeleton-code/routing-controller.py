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

    def add_broadcast_groups(self):
        mc_grp_id = 1
        customer_to_ports = self.get_customer_to_ports_mapping()
        for customer_id, ports in customer_to_ports.items():
            self.controller.mc_mgrp_create(mc_grp_id)
            handle = self.controller.mc_node_create(mc_grp_id, ports)
            self.controller.mc_node_associate(mc_grp_id, handle)
            ##
            self.controller.table_add("customer_multicast", "set_mcast_grp", [str(pw_id)], [str(mc_grp_id)])
            mc_grp_id += 1
        

    def process_packet(self, packet_data):
        ### use exercise 04-Learning as a reference point
        for macAddr, tunnel_id, pw_id, ingress_port in packet_data:
            if self.topo.get_hosts_connected_to(self.sw_name) == []: ##中间交换机
                self.controller.table_add('learning_table', 'NoAction', [str(macAddr)], [])
                return
        
        pass

    def get_all_ports(self, sw_name):
        ports = []
        for host in self.topo.get_hosts_connected_to(sw_name):
            ports.append(self.topo.node_to_node_port_num(sw_name, host))
        return ports

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
        self.tunnel_list = []
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

    def generate_tunnel_list(self):
        pe_switches = []
        for sw_name in self.topo.get_p4switches():
            if len(self.topo.get_hosts_connected_to(sw_name)) != 0:
                pe_switches.append(sw_name)
        pe_pairs = list(itertools.combinations(pe_switches, 2))
        for sw in pe_pairs:
            paths = self.topo.get_shortest_paths_between_nodes(sw[0], sw[1])
            for path in paths:
                tunnel_ports = self.get_path_ports(path)
                self.tunnel_list.append(tunnel_ports)

    def get_path_ports(self, path):
        ports = []
        for i in range(len(path) - 1):
            sw_name, next_sw_name = path[i], path[i + 1]
            port_num = self.topo.node_to_node_port_num(sw_name, next_sw_name)
            ports.append((sw_name, port_num))
        return ports
    

    def get_pw_id(self):
        customer_to_pw_id = {}
        for host in self.topo.get_hosts_connected_to(sw_name):
            port_num = self.topo.node_to_node_port_num(sw_name, host)
            customer_label = self.vpls_conf['hosts'][host]
            pw_id = hash(customer_label) %1024 + port_num
            customer_to_pw_id[port_num] = pw_id
        return customer_to_pw_id
    
    def get_tunnel_id(self):
        tunnel_to_ports = self.get_tunnel_to_ports_mapping()
        tunnel_id = 0 #初始tunnel_id
        tunnel_id_mapping = {}
        for tunnel, ports in tunnel_to_ports.items():
            for sw_name ,port_num in ports:
                sw_pw_id = self.get_pw_id(sw_name)
                if port_num in sw_pw_id:
                    pw_id = sw_pw_id[port_num]
                    self.controllers[sw_name].table_add("tunnel_table", "set_tunnel", [str(tunnel_id), str(pw_id)], [str(port_num)])
            tunnel_id_mapping[tuple(tunnel)] = tunnel_id
            tunnel_id += 1
        return tunnel_id_mapping

    def get_customer_to_ports_mapping(self):
        customer_to_ports = {}
        pe_switches = self.topo.get_p4switches()
        for sw_name in pe_switches:
            connected_hosts = self.topo.get_hosts_connected_to(sw_name)
            for host in connected_hosts:
                customer_id = self.vpls_conf['hosts'][host]
                port_num = self.topo.node_to_node_port_num(sw_name, host)
                if customer_id not in customer_to_ports:
                    customer_to_ports[customer_id] = []
                customer_to_ports[customer_id].append(port_num)
        return customer_to_ports

    def get_tunnel_to_ports_mapping(self):
        tunnel_to_ports = {}
        for tunnel in self.tunnel_list:
            ports = []
            for i in range(len(tunnel) - 1):
                sw_name, next_sw_name = tunnel[i], tunnel[i + 1]
                port_num = self.topo.node_to_node_port_num(sw_name, next_sw_name)
                ports.append((sw_name, port_num))
            tunnel_to_ports[tuple(tunnel)] = ports
        return tunnel_to_ports
    
    def get_pe_list(self):
        for sw_name in self.topo.get_p4switches().keys():
            if len(self.topo.get_hosts_connected_to(sw_name)) > 0 :
                self.pe_list.append(sw_name)
            elif len(self.topo.get_hosts_connected_to(sw_name)) == 0 :
                self.non_pe_list.append(sw_name)

    def get_all_tunnel_ports(self, sw_name):
        ports = []
        for tunnel in self.tunnel_list:
            if sw_name in tunnel:
                ports_t = self.get_tunnel_ports(tunnel, sw_name)
                for port in ports_t:
                    if not port in ports:
                        ports.append(port)
        return ports
    
    def get_all_non_tunnel_ports(self, sw_name):
        ports = []
        for host in self.topo.get_hosts_connected_to(sw_name):
            ports.append(self.topo.node_to_node_port_num(sw_name, host))
        return ports

    def process_network(self):


        for pe in self.pe_list:


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
