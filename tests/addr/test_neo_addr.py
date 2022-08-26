# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Imports
from bip_utils import CoinsConf, NeoAddr, NeoAddrDecoder, NeoAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_NIST256P1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_NIST256P1_PUB_KEY_INVALID, Nist256p1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03f4890a76acd4ec68537f1bfb5ed18121126babda24f65b6488e2ac57cf9becce",
        "address_dec": b"e1805874901439aa0697ae493603b704826cee62",
        "address_params": {
            "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
        },
        "address": "AcLDSGFoA3Re71QFF8nkpH31EoQjhoApkY",
    },
    {
        "pub_key": b"0217a644d0278b30015a15f363eae4c8ea7e619c234bc8be2accac531c2817e7d1",
        "address_dec": b"631985d8f74183a8780658162e5b12d8c024cd35",
        "address_params": {
            "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
        },
        "address": "AQos7r7repyb9AUzFuKc8voH4TS9XuQg7H",
    },
    {
        "pub_key": b"03e43cbeea55520fbd8e79b02a7e2ff5ddd881ac3f3603cb48d08423317b805831",
        "address_dec": b"65ac85c23feea989ffba6a317687a2b044fcf622",
        "address_params": {
            "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
        },
        "address": "AR3UZwqfjzvDuqUHwtdcGREqDSqpB3HDoP",
    },
    {
        "pub_key": b"02c23193a2ae86390b61ccae1302c4e3cfc3429b6d74282de13a368e8dbedbf50e",
        "address_dec": b"8c0f681b9d3ba062befe8693504611110ea75a98",
        "address_params": {
            "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
        },
        "address": "AUYShq2btNbP1qG4jeN1sBnzu2wv2EdvxF",
    },
    {
        "pub_key": b"02db975db10d75b3581945fb5e2b3d99e27ed2c50a9f2de19f2ec2a878fc4d9901",
        "address_dec": b"3cb0031040e8fdbf5dc5a5df608dc238c4d64719",
        "address_params": {
            "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
        },
        "address": "AMJm3XvdgZdHMK4T8XsWxKbrnPbTAC5ka7",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid version
    "A5CqiijKBC8WCQ7yiE2hP4XDGXgyLCe7hR",
    # Invalid checksum
    "AMJm3XvdgZdHMK4T8XsWxKbrnPbTB6k6Bx",
    # Invalid length
    "31eKhHWNQ4n4bPTKrf8BDNMy6C6eaiN6x",
    "iGdPQBViud19AeiELFFyDB6rjLj4S9snbFi",
]


#
# Tests
#
class NeoAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(NeoAddrEncoder, Nist256p1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(NeoAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            NeoAddrDecoder,
            {
                "ver": CoinsConf.Neo.ParamByKey("addr_ver"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            NeoAddrEncoder,
            {"ver": b"\x00"},
            TEST_NIST256P1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_NIST256P1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(NeoAddr is NeoAddrEncoder)
