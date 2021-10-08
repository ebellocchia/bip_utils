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
import unittest
from bip_utils import ZilAddr
from .test_addr_base import AddrBaseTestHelper
from .test_addr_const import *

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03abdbfd282eb1d9e64ea9fc4f912a514ed993b8dcaa13c7732ae91ebf48ecbd57",
        "addr_params": {},
        "address": "zil1gm0cxtn8lcgnl8yhwg2579zhkuck7lhtutmelc",
    },
    {
        "pub_key": b"03f33e10bf145cd1936b054c5b32a3fa0d865c80fb0b76c9a6398f21b429f1efeb",
        "addr_params": {},
        "address": "zil1328lxdjxm0qy2npqu58cvn3tmlgq67af7gdqlc",
    },
    {
        "pub_key": b"039d6004660240dfa2c818e97f1056504c7bb3367602615fcb6cc894ff0098b14b",
        "addr_params": {},
        "address": "zil1mehmxyydest5yv5ldplzjfpvhgmw6h6ke5dq0g",
    },
    {
        "pub_key": b"03228350bd31aaa0fa07446e161840cb48d97752956ee362e28f79df764f24bd96",
        "addr_params": {},
        "address": "zil1sa0ser5u3p7pm08v8sv6696v4386jk30cd777w",
    },
    {
        "pub_key": b"03f6d222b568d850218c1901f4e8dc3f0eba861c5b59ef1726801274175821cb30",
        "addr_params": {},
        "address": "zil1nv4nt7kq6fsup2jmqlxa6855ccx9qsvylxt3vh",
    },
]


#
# Tests
#
class ZilAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, ZilAddr, Secp256k1PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             ZilAddr,
                                             {},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
