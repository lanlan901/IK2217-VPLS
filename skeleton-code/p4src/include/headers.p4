/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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
}

header rtt_t{
    bit<16> pw_id;
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<48> rtt;
}

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t 		 ipv4;
    cpu_t        cpu;
    rtt_t        rtt;
}

