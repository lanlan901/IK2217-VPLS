/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes 
#include "include/headers.p4"
#include "include/parsers.p4"

const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> RTT_ETHER_TYPE = 0x5678;

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action forward (egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action tunnel_forward (egressSpec_t port) {
        //hdr.ethernet_tunnel.setValid();
        //hdr.ethernet.etherType = TYPE_TUNNEL;
        //hdr.tunnel.tunnel_id = tunnel_id;
        //hdr.tunnel.pw_id = pw_id;
        standard_metadata.egress_spec = port;
    }

    //TASK 1 : normal forwarding table
    table forward_table {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table tunnel_forward_table {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.tunnel.tunnel_id: exact;
            hdr.tunnel.pw_id: exact;
        }
        actions = {
            tunnel_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    //TASK 2: ECMP
    action ecmp_group (bit<14> ecmp_group_id, bit<16> num_nhops) {
        hash(meta.ecmp_hash,
            HashAlgorithm.crc32,
            (bit<1>)0,
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},
            num_nhops);
        meta.ecmp_group_id = ecmp_group_id;
    }

    action set_nhop(egressSpec_t port) {
        // hdr.ethernet.srcAddr = srcAddr;
        // hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action decap_nhop(egressSpec_t port){
        hdr.tunnel.setInValid();
        standard_metadata.egress_spec = port;
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            NoAction;
            set_nhop;
        }
        size = 1024;
        default_action = NoAction;
    }
    table tunnel_ecmp {
        key = {
            standard_metadata.ingress_port: exact;
            meta.tunnel_id: exact;
        }
        actions = {
            decap_nhop;
            set_nhop;
            ecmp_group;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    //TASK 3 : multicasting
    action set_mcast_grp (bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    table customer_flooding {
        key = {
            hdr.tunnel.pw_id : exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table tunnel_flooding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    //TASK 4 : L2 learning
    action mac_learn() {
        meta.ingress_port = standard_metadata.ingress_port;
        clone3(CloneType.I2E, 100, meta);
    }
    table learning_table {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            mac_learn;
            NoAction;
        }
        size = 1024;
        default_action = mac_learn;
    }

    action encap(tunnel_id_t tunnel_id, pw_id_t pw_id) {
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id = tunnel_id;
        hdr.tunnel.pw_id = pw_id;
    }

    table whether_encap {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ethernet.srcAddr: exact;
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            encap;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }


    apply {
        learning_table.apply();
        //匹配进入端口做转发（什么都不做留到else中处理）/封装
        whether_encap.apply();// encap or NoAction

        if (hdr.tunnel.isValid()) {
            switch (tunnel_ecmp.apply().action_run) {// decap_nhop or set_nhop or ecmp_group or noaction
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
             }

            tunnel_flooding.apply();
        }
        else {
            
            if (forward_table.apply().hit) { }
            else if (hdr.ipv4.isValid()) {
                switch (ipv4_lpm.apply().action_run){
                    ecmp_group: { ecmp_group_to_nhop.apply(); }
                }
            }
            else if (tunnel_forward_table.apply().hit) { }
            else customer_flooding.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop_2(){
        mark_to_drop();
    }
    apply {
        if (standard_metadata.instance_type == 1){
            hdr.cpu.setValid();
            hdr.cpu.srcAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
            if (hdr.tunnel.isValid()) {
                hdr.cpu.tunnel_id = hdr.tunnel.tunnel_id;
                hdr.cpu.pw_id = hdr.tunnel.pw_id;
                hdr.cpu.ingress_port = 0;
            } else {
                hdr.cpu.tunnel_id = 0;
                hdr.cpu.pw_id = 0;
                hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            truncate((bit<32>)22);
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
