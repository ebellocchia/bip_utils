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
from bip_utils import XtzAddrPrefixes, XtzAddr
from .test_addr_base import AddrBaseTestHelper
from .test_addr_const import *

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00c984cd868dae74bc8879ed6079c53cfb328e0bc095a1d587c26c4d79bdb4f354",
        "addr_params": {"prefix": XtzAddrPrefixes.TZ1},
        "address": "tz1VgeyGiyNEA2JfqJH4utRqox9fkN2uwhbp",
    },
    {
        "pub_key": b"00ade94377eb07a7f406937c4b0e1aa6e64f78ba0e9faa3fbe43386a5a20f79804",
        "addr_params": {"prefix": XtzAddrPrefixes.TZ1},
        "address": "tz1bqff5qsRZ3ix1Er6XXs8uUKYuzvRyVa8p",
    },
    {
        "pub_key": b"003dad9044f1eec4b981fbdb8f0a3128c62d6f64dde84220a0c5aba12711224f45",
        "addr_params": {"prefix": XtzAddrPrefixes.TZ1},
        "address": "tz1ZNoP4tpSAHs1iLbobCvhF8t9DDaoCTzR8",
    },
    {
        "pub_key": b"2ae8dfda6cfa73f759a84a328c0f1003541adf647e2d85f6c8c8f42f7045e217",
        "addr_params": {"prefix": XtzAddrPrefixes.TZ1},
        "address": "tz1cTxNAJ2NvkeyjpZKp4WpeqqkRPYX7HgGY",
    },
    {
        "pub_key": b"804e68f00f2a25fe4abc55022757de59604c874f91cc0fb60da580ad4481992f",
        "addr_params": {"prefix": XtzAddrPrefixes.TZ1},
        "address": "tz1NPgUeafMfD7VZbsKkzoJiR8pRynViiTE3",
    },
]


#
# Tests
#
class XtzAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, XtzAddr, Ed25519PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             XtzAddr,
                                             {"prefix": XtzAddrPrefixes.TZ1},
                                             TEST_ED25519_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_ED25519_PUB_KEY_INVALID)

    # Test invalid parameters
    def test_invalid_params(self):
        AddrBaseTestHelper.test_invalid_params(self, XtzAddr, TEST_ED25519_PUB_KEY, {"prefix": 0})
