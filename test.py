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
import crcmod
from scapy.all import *

from ptf import config, mask
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

dev_id = 0
p4_program_name = "tna_random"

logger = get_logger()
swports = get_sw_ports()

"""
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
"""

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


    def readRange(self):
        resp = self.register_table.entry_get(
            self.target, flags={"from_hw":True})

        all_data = []

        try:
            while True:
                x, _ = next(resp)
                all_data.append(sum(x.to_dict()['SwitchIngress.test_reg.val']))
        except StopIteration:
            print("Stop iteration")
            
        print(all_data, len(all_data))

        #data, _ = next(resp)
        #data_dict = data.to_dict()

        #print(data)

        #return data_dict[self.regArrayName + "." + self.val_field]

    def writeIndex(self, index, val):
        self.register_table.entry_add(
            self.target,
            [self.register_table.make_key(
                [gc.KeyTuple('$REGISTER_INDEX', index)])],
            [self.register_table.make_data(
                [gc.DataTuple(self.regArrayName + "." + self.val_field, val)
                 ])])


def crc_from_eth(src):
    hash2_func = crcmod.predefined.mkCrcFun('crc-32-bzip2')
    src_hex = int(src[6:17].replace(":", ""), 16)
    return hash2_func(struct.pack("!I", src_hex)) & 0xffffffff
    #2458715652
    
class TestAddingToFilter(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        try:
            t = AsyncSniffer(count=0, iface="veth250")
            t.start()
            test_reg = RegisterArray(
                self.interface, "tna_random", "SwitchIngress.test_reg")

            test_dst = '11:11:11:11:11:14'
            print(crc_from_eth(test_dst))

            print("Send an outgoing packet.\n")



            for _ in range(0,200):
                outgoing_ipkt = testutils.simple_udp_packet(eth_dst=test_dst,
                                                            eth_src='11:11:11:11:11:77',
                                                            ip_src='1.2.3.4',
                                                            ip_dst='100.99.98.97',
                                                            ip_id=101,
                                                            ip_ttl=64,
                                                            udp_sport=0x1234,
                                                            udp_dport=0xabcd)
                testutils.send_packet(self, swports[0], outgoing_ipkt)

            results = t.stop()
            print(results)
            print(results[1]["Ether"].dst)
            """
            (rcv_dev, rcv_port, rcv_pkt, pkt_time) = \
                testutils.dp_poll(self, dev_id, swports[1], timeout=2)

            nrcv = bytes2hex(rcv_pkt)[52:60]  # IP.src
            rand_val = int(nrcv, 16)  # convert hex value to int
            print(rand_val)

            print("Test that we can now receive incoming packet.\n")
            ipkt = testutils.simple_udp_packet(eth_dst='11:11:11:11:11:77',
                                               eth_src=test_dst,
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               udp_sport=0x1234,
                                               udp_dport=0xabcd)

            testutils.send_packet(self, swports[1], ipkt)

            (rcv_dev, rcv_port, rcv_pkt, pkt_time) = \
                testutils.dp_poll(self, dev_id, swports[0], timeout=2)

            nrcv = bytes2hex(rcv_pkt)[52:60]  # IP.src
            rand_val = int(nrcv, 16)
            print(rand_val)

            test_reg.readRange()
            """

        finally:
            pass


class TestFilterWorks(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        # test_reg = RegisterArray(
        #     self.interface, "tna_random", "SwitchIngress.test_reg")

        print("Test that unlisted incoming packet is blocked.\n")
        ipkt = testutils.simple_udp_packet(eth_dst='11:11:11:11:11:77',
                                           eth_src='11:11:11:11:23:17',
                                           ip_src='1.2.3.4',
                                           ip_dst='100.99.98.97',
                                           ip_id=101,
                                           ip_ttl=64,
                                           udp_sport=0x1234,
                                           udp_dport=0xabcd)

        testutils.send_packet(self, swports[1], ipkt)
        (rcv_dev, rcv_port, rcv_pkt, pkt_time) = \
            testutils.dp_poll(self, dev_id, swports[0], timeout=2)

        assert rcv_pkt == None
