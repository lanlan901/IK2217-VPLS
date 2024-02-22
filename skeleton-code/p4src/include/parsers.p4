/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet_outer;
    }

    state parse_ethernet_outer {
        packet.extract(hdr.ethernet_outer);
        transition select(hdr.ethernet_outer.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_TUNNEL: parse_tunnel;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_tunnel{
        packet.extract(hdr.tunnel);
        transition parse_ethernet;
    }

    state parse_ethernet{
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet_outer);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}