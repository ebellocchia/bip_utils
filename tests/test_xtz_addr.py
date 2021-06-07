# Copyright (c) 2020 Emanuele Bellocchia
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
import binascii
import unittest
from bip_utils import XtzAddr, Ed25519PublicKey, Secp256k1PublicKey
from .test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_SECP256K1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00c984cd868dae74bc8879ed6079c53cfb328e0bc095a1d587c26c4d79bdb4f354",
        "address": "tz1VgeyGiyNEA2JfqJH4utRqox9fkN2uwhbp",
    },
    {
        "pub_key": b"00ade94377eb07a7f406937c4b0e1aa6e64f78ba0e9faa3fbe43386a5a20f79804",
        "address": "tz1bqff5qsRZ3ix1Er6XXs8uUKYuzvRyVa8p",
    },
    {
        "pub_key": b"003dad9044f1eec4b981fbdb8f0a3128c62d6f64dde84220a0c5aba12711224f45",
        "address": "tz1ZNoP4tpSAHs1iLbobCvhF8t9DDaoCTzR8",
    },
    {
        "pub_key": b"002ae8dfda6cfa73f759a84a328c0f1003541adf647e2d85f6c8c8f42f7045e217",
        "address": "tz1cTxNAJ2NvkeyjpZKp4WpeqqkRPYX7HgGY",
    },
    {
        "pub_key": b"00804e68f00f2a25fe4abc55022757de59604c874f91cc0fb60da580ad4481992f",
        "address": "tz1NPgUeafMfD7VZbsKkzoJiR8pRynViiTE3",
    },
]


#
# Tests
#
class XtzAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], XtzAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], XtzAddr.EncodeKey(Ed25519PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, XtzAddr.EncodeKey, Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_COMPR_PUB_KEY)))
        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, XtzAddr.EncodeKey, binascii.unhexlify(test))
