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
from bip_utils import CoinsConf, NeoN3Addr, NeoN3AddrDecoder, NeoN3AddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_NIST256P1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_NIST256P1_PUB_KEY_INVALID, Nist256p1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03cdb067d930fd5adaa6c68545016044aaddec64ba39e548250eaea551172e535c",
        "address_dec": b"1a9e04be3c7a2b41e936a584e79bd9e93a52dea5",
        "address_params": {
            "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
        },
        "address": "NNLi44dJNXtDNSBkofB48aTVYtb1zZrNEs",
    },
    {
        "pub_key": b"0217a644d0278b30015a15f363eae4c8ea7e619c234bc8be2accac531c2817e7d1",
        "address_dec": b"2f385693536d2f21503b5d39af0143ccf124069a",
        "address_params": {
            "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
        },
        "address": "NQDeSDaiFio5DzdcKuzGqhopg1VC9tCM1T",
    },
    {
        "pub_key": b"03e43cbeea55520fbd8e79b02a7e2ff5ddd881ac3f3603cb48d08423317b805831",
        "address_dec": b"084adc07c697ee910b4865c3c6fda82135e33d57",
        "address_params": {
            "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
        },
        "address": "NLfpGcsubYLnTqb9UfAxCYe9S5xniGSZyR",
    },
    {
        "pub_key": b"02c23193a2ae86390b61ccae1302c4e3cfc3429b6d74282de13a368e8dbedbf50e",
        "address_dec": b"b36f5d32fdc1d6830e574dfcbdc887a74b0435d8",
        "address_params": {
            "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
        },
        "address": "NcGjYobCq2B8H9jiqUEryfcZ5f58UtKdEQ",
    },
    {
        "pub_key": b"02db975db10d75b3581945fb5e2b3d99e27ed2c50a9f2de19f2ec2a878fc4d9901",
        "address_dec": b"634c209d6978199bb888ebb7040987a6c84c6fc0",
        "address_params": {
            "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
        },
        "address": "NUy1HAv7Ns1ZMSiSUKsZFFDNCZW387PAYb",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid version
    "NmgK3Avb5iM6BsKqq5WNchjHBPqxc3MRwg",
    # Invalid checksum
    "NNLi44dJNXtDNSBkofB48aTVYtb1zbTTMi",
    # Invalid length
    "5tW7VEbzjheFAjiJZkXdxhqy1gxzY2axz",
    "2dKBzCX1Dg3K3bcAULwVNpSfw1kh8uKR9GGg",
]


#
# Tests
#
class NeoN3AddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(NeoN3AddrEncoder, Nist256p1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(NeoN3AddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            NeoN3AddrDecoder,
            {
                "ver": CoinsConf.NeoN3.ParamByKey("addr_ver"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            NeoN3AddrEncoder,
            {"ver": b"\x00"},
            TEST_NIST256P1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_NIST256P1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(NeoN3Addr is NeoN3AddrEncoder)
