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
    bit<32> fingerprint_input;
    bit<32> fingerprint;
    bool action_result;
    // bit<32> return_val;
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

        // Start with some random values for easy debugging
        ig_md.fingerprint = 42;
        ig_md.fingerprint_input = 43;
        ig_md.action_result = true;
        // ig_md.return_val = 44;

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

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    // Setup hash function for fingerprints
    CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                        false, 
                        false, 
                        false, 
                        32w0xFFFFFFFF,
                        32w0xFFFFFFFF
                        ) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) fingerprint;

    // Wrap hash in action for multi-use
    action action_compute_fingerprint() {
        ig_md.fingerprint = fingerprint.get({
            ig_md.fingerprint_input
        });
    }

    // Register array for storing cuckoo filter
    Register<reg_value, bit<10>>(size=32w1024) test_reg;

    // Compute fingerprint and check it matches reg array entry at idx
    RegisterAction<reg_value, bit<10>, bool>(test_reg) read_val = {
        void apply(inout reg_value val, out bool rv) {
            rv = val.val == ig_md.fingerprint;
        }
    };

    // Compute fingerprint and insert into reg array entry at idx
    RegisterAction<reg_value, bit<10>, bit<32>>(test_reg) insert_flow = {
        void apply(inout reg_value val, out bit<32> rv) {    
            val.val = ig_md.fingerprint;
            rv = 1;
        }
    };

    action action_check_membership() {
        ig_md.action_result = read_val.execute(ig_md.fingerprint[9:0]);
    }
    action action_insert_flow() {
        insert_flow.execute(ig_md.fingerprint[9:0]);
    }

    apply {
        // If outgoing packet
        if (ig_intr_md.ingress_port == 0) {
            ig_md.fingerprint_input = hdr.ethernet.dst_addr[31:0];
            action_compute_fingerprint();
            action_insert_flow();
            // ig_md.return_val = ig_md.fingerprint;

            // Forward to outgoing port
            ig_tm_md.ucast_egress_port = 1;
        
        // If incoming packet
        } else if (ig_intr_md.ingress_port == 1) {
            ig_md.fingerprint_input = hdr.ethernet.src_addr[31:0];
            action_compute_fingerprint();
            action_check_membership();
            // ig_md.return_val = ig_md.fingerprint;

            // Forwawrd to incoming port
            ig_tm_md.ucast_egress_port = 0;
        }

        // Drop if not in filter (i.e. disallowed flow)
        if (ig_intr_md.ingress_port == 1 && !ig_md.action_result) {
           drop();
        }

        // Using this for debugging 
        // hdr.ipv4.src_addr = ig_md.return_val;

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
