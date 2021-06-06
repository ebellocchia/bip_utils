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
from bip_utils import OneAddr, Ed25519PublicKey, Secp256k1PublicKey

# Some keys randomly taken
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

# Tests for invalid keys
TEST_VECT_KEY_INVALID = [
    # Private key
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
    # Compressed public key with valid length but wrong version
    b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
    # Compressed public key with invalid length
    b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
    # Uncompressed public key with valid length but wrong version
    b"058ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
    # Uncompressed public key with invalid length
    b"04fd87569e9af6015d9d938c67c68fcdf5440d3c235eccbc1195a1924bba90e5e1954cb6d841054791ac227a8c11f79f77d24a20b238402c5424c8e436bb49",
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
            self.assertEqual(test["address"], OneAddr.ToAddress(key_bytes))
            self.assertEqual(test["address"], OneAddr.ToAddress(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, OneAddr.ToAddress, Ed25519PublicKey(b"000102030405060708090a0b0c0d0e0f"))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, OneAddr.ToAddress, binascii.unhexlify(test))
