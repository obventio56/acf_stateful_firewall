################################################################################
#  INTEL CONFIDENTIAL
#
#  Copyright (c) 2021 Intel Corporation
#  All Rights Reserved.
#
#  This software and the related documents are Intel copyrighted materials,
#  and your use of them is governed by the express license under which they
#  were provided to you ("License"). Unless the License provides otherwise,
#  you may not use, modify, copy, publish, distribute, disclose or transmit this
#  software or the related documents without Intel's prior written permission.
#
#  This software and the related documents are provided as is, with no express or
#  implied warranties, other than those that are expressly stated in the License.
#################################################################################


import logging
import socket
import struct
import math
import random

from ptf import config, mask
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

dev_id = 0
p4_program_name = "tna_random"

logger = get_logger()
swports = get_sw_ports()


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def stdev(vals):
    n = len(vals)
    if n <= 1:
        return 0.0

    mean = sum(vals) / float(len(vals))
    sd = 0.0
    for val in vals:
        sd += (float(val) - mean) ** 2
    sd = math.sqrt(sd / float(n - 1))
    return sd


def randomSrc():
    components = []
    for _ in range(6):
        components.append(str(random.randint(0, 99)))
    return ":".join(components)

""" A class of abstractions for interacting with register arrays
"""
class RegisterArray():
    def __init__(self, interface, p4Name, regArrayName):
        self.val_field = "val"
        self.regArrayName = regArrayName
        self.bfrt_info = interface.bfrt_info_get(p4Name)
        self.register_table = self.bfrt_info.table_get(regArrayName)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def readIndex(self, index):
        resp = self.register_table.entry_get(
            self.target,
            [self.register_table.make_key(
                [gc.KeyTuple('$REGISTER_INDEX', index)])],
            {"from_hw": False})
        data, _ = next(resp)
        data_dict = data.to_dict()
        return data_dict[self.regArrayName + "." + self.val_field]

    def writeIndex(self, index, val):
        self.register_table.entry_add(
            self.target,
            [self.register_table.make_key(
                [gc.KeyTuple('$REGISTER_INDEX', index)])],
            [self.register_table.make_data(
                [gc.DataTuple(self.regArrayName + "." + self.val_field, val)
                 ])])


class TestRandom(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        try:

            test_reg = RegisterArray(
                self.interface, "tna_random", "SwitchIngress.test_reg")
            # expected mean and stdev from 32b unsigned uniform random
            exp_mean = (pow(2, 32) - 1) / 2.0
            exp_std = (pow(2, 32) - 1) / math.sqrt(12)

            # compute mean and std from samples
            num_samples = 1000
            rand_vals = []
            print("\nInject %s packets and get random value in srcip field." %
                  num_samples)
            print("It may take time with model.\n")
            for i in range(num_samples):

                randomIdx = random.randint(0, 1023)
                randomValue = random.randint(0, 1 << 31)
                test_reg.writeIndex(randomIdx, randomValue)
                
                print("Setting index : " + str(randomIdx) +
                      " to value: " + str(randomValue))

                readIdxVal = test_reg.readIndex(randomIdx)
                assert readIdxVal[0] == randomValue

                ipkt = testutils.simple_udp_packet(eth_dst='11:11:11:11:11:11',
                                                   eth_src=randomIdx,
                                                   ip_src='1.2.3.4',
                                                   ip_dst='100.99.98.97',
                                                   ip_id=101,
                                                   ip_ttl=64,
                                                   udp_sport=0x1234,
                                                   udp_dport=0xabcd)

                testutils.send_packet(self, swports[0], ipkt)
                (rcv_dev, rcv_port, rcv_pkt, pkt_time) = \
                    testutils.dp_poll(self, dev_id, swports[0], timeout=2)
                nrcv = bytes2hex(rcv_pkt)[52:60]  # IP.src
                # print("\n### Received pkt :\n")
                # nrcv.show2()
                # hexdump(nrcv)
                rand_val = int(nrcv, 16)  # convert hex value to int
                rand_vals.append(rand_val)
                print("Read value from register is : " + str(rand_val))
                assert rand_val == randomValue


            # compare mean and std
            mean = sum(rand_vals) / float(len(rand_vals))
            std = stdev(rand_vals)
            # print(("Expected Mean : " + str(exp_mean)))
            print(("Observed Mean : " + str(mean)))
            # print(("Expected Stdev : " + str(exp_std)))
            print(("Observed Stdev : " + str(std)))
            print(("Observed min : " + str(min(rand_vals))))
            print(("Observed max : " + str(max(rand_vals))))

            # assert abs(mean - exp_mean) / float(exp_mean) < 0.1
            # assert abs(std - exp_std) / float(exp_std) < 0.1

        finally:
            pass
