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
import binascii
import unittest
from bip_utils import OneAddr, Ed25519PublicKey, Ed25519Blake2bPublicKey, Nist256p1PublicKey, Secp256k1PublicKey
from .test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, TEST_ED25519_COMPR_PUB_KEY, TEST_NIST256P1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03c4002dceb4728c2d66602fff93b75e65a61c0e933bdf15d2ba2add16a1069730",
        "address": "one1exasl02q0arrfkfmafvp7eq4samqa7m7qe4lv6",
    },
    {
        "pub_key": b"0223f8e3d044ed176e016eba89f4ed936a0f8a1c4f01cc51de56c42d331717309c",
        "address": "one1y36sqtpvnqujtdfl6mrljn0fr7ht3d5q5rtwf2",
    },
    {
        "pub_key": b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2",
        "address": "one1cjt78d63ara62afuqgna8ncnmfz2qzx2f4g0km",
    },
    {
        "pub_key": b"021c108820fc83a01e4380d50187dbe3ea889a4c18ad3cab6562e71438fa48bdfc",
        "address": "one144ku53n048eeyth8sl77k9r60peqxd803t4ml5",
    },
    {
        "pub_key": b"03f72613f6c9f2a7f20a2d59e32ae996e9b4e3c45b9bf772cf14e8f8bea1065abe",
        "address": "one1c3x93ajl50cdwy6a3agrmphgnsa5rwkptdy0yj",
    },
]


#
# Tests
#
class OneAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], OneAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], OneAddr.EncodeKey(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, OneAddr.EncodeKey, Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, OneAddr.EncodeKey, Ed25519Blake2bPublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, OneAddr.EncodeKey, Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)))

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, OneAddr.EncodeKey, binascii.unhexlify(test))
