from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from multiprocessing import Pool
import threading
import json
import ipaddress

class CpuHeader(Packet):
    name = 'CpuPacket'
    ### define your own CPU header

class RttHeader(Packet):
    name = 'RttPacket'
    fields_desc = [BitField('customer_id',0,16), BitField('ip_addr_src', 0, 32), BitField('ip_addr_dst', 0, 32), BitField('rtt',0,48)]

class EventBasedController(threading.Thread):
    def __init__(self, params):
        super(EventBasedController, self).__init__()
        self.topo = Topology(db="topology.db")
        self.sw_name = params["sw_name"]
        self.cpu_port_intf = params["cpu_port_intf"]
        self.thrift_port = params["thrift_port"]
        self.id_to_switch = params["id_to_switch"]
        self.controller = SimpleSwitchAPI(thrift_port)

    def run(self):
        sniff(iface=self.cpu_port_intf, prn=self.recv_msg_cpu)

    def recv_msg_cpu(self, pkt):
        print "received packet at " + str(self.sw_name) + " controller"

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header = CpuHeader(packet.payload)
            self.process_packet([(None)]) ### change None with the list of fields from the CPUHeader that you defined
        elif packet.type == 0x5678:
            rtt_header = RttHeader(packet.payload)
            self.process_packet_rtt([(rtt_header.customer_id,rtt_header.ip_addr_src,rtt_header.ip_addr_dst,rtt_header.rtt)])

    def process_packet(self, packet_data):
        ### write your learning logic here
        ### use exercise 04-Learning as a reference point
        pass

    def process_packet_rtt(self, packet_data):
        for customer_id, ip_addr_src, ip_addr_dst, rtt in packet_data:
            print("Customer_id: " + str(customer_id))
            print("SourceIP: " +  str(ipaddress.IPv4Address(ip_addr_src)))
            print("DestinationIP: " + str(ipaddress.IPv4Address(ip_addr_dst)))
            print("RTT: " + str(rtt))

class RoutingController(object): 

    def __init__(self, vpls_conf_file):

        self.topo = Topology(db="topology.db")
        self.cpu_ports = {x:self.topo.get_cpu_port_index(x) for x in self.topo.get_p4switches().keys()}
        self.controllers = {}
        self.vpls_conf_file = vpls_conf_file
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.add_mirror()
        self.extract_customers_information()
        self.switch_to_id = {sw_name:self.get_switch_id(sw_name) for sw_name in self.topo.get_p4switches().keys()}
        self.id_to_switch = {self.get_switch_id(sw_name):sw_name for sw_name in self.topo.get_p4switches().keys()}

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


    def process_network(self):
        ### logic to be executed at the start-up of the topology
        ### hint: compute ECMP paths here
        ### use exercise 08-Simple Routing as a reference
        pass

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print "Error: vpls.conf file missing"
        sys.exit()
    vpls_conf_file = sys.argv[1]
    controller = RoutingController(vpls_conf_file)
    controller.process_network()
    thread_list = []
    for sw_name in controller.topo.get_p4switches().keys():
        cpu_port_intf = str(controller.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1"))
        thrift_port = controller.topo.get_thrift_port(sw_name)
        id_to_switch = controller.id_to_switch
        params ={}
        params["sw_name"] = sw_name
        params["cpu_port_intf"]= cpu_port_intf 
        params["thrift_port"]= thrift_port
        params["id_to_switch"]= id_to_switch
        thread = EventBasedController(params )
        thread.setName('MyThread ' + str(sw_name))
        thread.daemon = True
        thread_list.append(thread)
        thread.start()
    for thread in thread_list:
        thread.join()
    print ("Thread has finished")
