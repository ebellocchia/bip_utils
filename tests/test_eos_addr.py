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
from bip_utils import EosAddr, Secp256k1PublicKey
from .test_ecc import (
    TEST_VECT_SECP256K1_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0290ae9e1951967ea073b242c4e6dba5e728d9f4dca4a7161e1ec7f22114cd72c4",
        "address": "EOS5zD4eXtvBmLhzmj9CtvuG2wxwuKcTbYxYwsGpPvKe68ExHjJsc",
    },
    {
        "pub_key": b"03f0c00e0faa983a664b526a3c9fc09362ac1a200159a021ce2ffe07d7938ff725",
        "address": "EOS8fGAt3L5oXQeXwnZDpWvXeipNi8FcrfUbL79TiD55za9CZo3pr",
    },
    {
        "pub_key": b"0381c6e21d718774ec71acf702b2f4a4df93ff680096840ad47c0487bd595ecc65",
        "address": "EOS7pPWL22sB1tbTkec6zDsSW2GpNE6faQzQJJ9CGc7CC1Q9FQ8r2",
    },
    {
        "pub_key": b"03771a273de43fd0e01ce40dfbb6fe487d0cc88caad8e3af6e3865d39acf534ad3",
        "address": "EOS7jgqNtYBCGb4fLDFepiBBxFbpcEPTXCKLihH9GtKf4QiGcV2Xo",
    },
    {
        "pub_key": b"03c2623b9c450d7e5c16c02b41a34b7eff782481a52d99060c8e6e6188e154a98a",
        "address": "EOS8JqoRy3T3ok9cN2WtcPkFDYowcpNTtwBs951NLxN56857KDHXa",
    },
]


#
# Tests
#
class EosAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], EosAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], EosAddr.EncodeKey(Secp256k1PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, EosAddr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, EosAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, EosAddr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY)
        self.assertRaises(TypeError, EosAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, EosAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, EosAddr.EncodeKey, binascii.unhexlify(test))
