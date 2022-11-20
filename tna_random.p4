/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

struct metadata_t {
}

#include "common/headers.p4"
#include "common/util.p4"

struct reg_value {
    bit<32>     val;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t
                                ig_intr_dprsr_md
                              ) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    BypassEgress() bypass_egress;

    Register<reg_value, bit<32>>(size=32w1024) test_reg;

    // define 32b random number generator
    // Random<bit<32>>() rnd1;

    // DirectRegisterAction<bit<32>, bit<32>>(test_reg_dir) test_reg_dir_action = {
    //     void apply(inout bit<32> value, out bit<32> read_value){
    //         value = value + 1;
    //         read_value = value;
    //     }
    // };

    RegisterAction<reg_value, bit<32>, bit<32>>(test_reg) register_table_action = {
        void apply(inout reg_value val, out bit<32> rv) {
            rv = val.val;
        }
    };

    // CRCPolynomial<bit<32>>(32w0x04C11DB7, 
    //                    false, 
    //                    false, 
    //                    false, 
    //                    32w0xFFFFFFFF,
    //                    32w0xFFFFFFFF
    //                    ) poly2;
    //Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) hash2;
    bit<32> idx;

    apply {
        idx = hdr.ethernet.src_addr[31:0];
        hdr.ipv4.src_addr = register_table_action.execute(idx);

        // get a random value from the generator
        // put into ipv4 src ip
        //hdr.ipv4.src_addr = rnd1.get();

        // forward the pkt back to the incoming port
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

        // No need for egress processing, skip it and use empty controls for egress.
        // Demonstrate how to use a control for that.
        bypass_egress.apply(ig_tm_md);
    }
}

Pipeline(SwitchIngressParser(),
       SwitchIngress(),
       SwitchIngressDeparser(),
       EmptyEgressParser(),
       EmptyEgress(),
       EmptyEgressDeparser()) pipe;

Switch(pipe) main;
