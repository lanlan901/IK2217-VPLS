/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_TUNNEL = 0x2345;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;
typedef bit<16> tunnel_id_t;
typedef bit<16> pw_id_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header cpu_t{
    bit<48> srcAddr;
    bit<16> ingress_port;
    tunnel_id_t tunnel_id;
    pw_id_t dst_pw_id;
    pw_id_t src_pw_id;
}

header tunnel_t{
    tunnel_id_t tunnel_id;
    pw_id_t dst_pw_id;
    pw_id_t src_pw_id;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<9> ingress_port;
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
}

struct headers {
    ethernet_t   ethernet_outer;
    ethernet_t   ethernet;
    ipv4_t 	     ipv4;
    cpu_t        cpu;
    tunnel_t     tunnel;
    tcp_t        tcp;
}

