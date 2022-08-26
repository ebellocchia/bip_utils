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
from bip_utils import ZilAddr, ZilAddrDecoder, ZilAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03abdbfd282eb1d9e64ea9fc4f912a514ed993b8dcaa13c7732ae91ebf48ecbd57",
        "address_dec": b"46df832e67fe113f9c9772154f1457b7316f7eeb",
        "address_params": {},
        "address": "zil1gm0cxtn8lcgnl8yhwg2579zhkuck7lhtutmelc",
    },
    {
        "pub_key": b"03f33e10bf145cd1936b054c5b32a3fa0d865c80fb0b76c9a6398f21b429f1efeb",
        "address_dec": b"8a8ff33646dbc0454c20e50f864e2bdfd00d7ba9",
        "address_params": {},
        "address": "zil1328lxdjxm0qy2npqu58cvn3tmlgq67af7gdqlc",
    },
    {
        "pub_key": b"039d6004660240dfa2c818e97f1056504c7bb3367602615fcb6cc894ff0098b14b",
        "address_dec": b"de6fb3108dcc1742329f687e29242cba36ed5f56",
        "address_params": {},
        "address": "zil1mehmxyydest5yv5ldplzjfpvhgmw6h6ke5dq0g",
    },
    {
        "pub_key": b"03228350bd31aaa0fa07446e161840cb48d97752956ee362e28f79df764f24bd96",
        "address_dec": b"875f0c8e9c887c1dbcec3c19ad174cac4fa95a2f",
        "address_params": {},
        "address": "zil1sa0ser5u3p7pm08v8sv6696v4386jk30cd777w",
    },
    {
        "pub_key": b"03f6d222b568d850218c1901f4e8dc3f0eba861c5b59ef1726801274175821cb30",
        "address_dec": b"9b2b35fac0d261c0aa5b07cddd1e94c60c504184",
        "address_params": {},
        "address": "zil1nv4nt7kq6fsup2jmqlxa6855ccx9qsvylxt3vh",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "zal1cklkcug0caxsl72c4av9hwt8tlm5a587hk2mzt",
    # No separator
    "zilmehmxyydast5yv5ldplzjfpvhgmw6h6ke5dq0g",
    # Invalid checksum
    "zil1cklkcug0caxsl72c4av9hwt8tlm5a5879lca4s",
    # Invalid encoding
    "zil1mehmxyydbst5yv5ldplzjfpvhgmw6h6ke5dq0g",
    # Invalid lengths
    "zil1hak8zr78f58ljk90tpdmje6l7a8dpls2gmxek",
    "zil19mzm7mr3plr56rletzh4skaeva0lwnkslc9450r3",
]


#
# Tests
#
class ZilAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(ZilAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(ZilAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(ZilAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            ZilAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(ZilAddr is ZilAddrEncoder)
