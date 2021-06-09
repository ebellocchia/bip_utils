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
from bip_utils import SubstrateAddr, Ed25519PublicKey, Nist256p1PublicKey, Secp256k1PublicKey
from .test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_SECP256K1_COMPR_PUB_KEY, TEST_NIST256P1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
        "version": b"\x00",
        "address": "12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU",
    },
    {
        "pub_key": b"00e8474b9c29d44d45c0755077d4f8a21dc611c76e36e261773b5410b8e5bf15a1",
        "version": b"\x07",
        "address": "nmB6fx6ehzHwA4wyfFVZig28cCAcathGwfShrNsvueitzZC",
    },
    {
        "pub_key": b"008b4564d4b6be05d6ead16d246c5e30773da9459040370284b57c944a3d0a1481",
        "version": b"\x12",
        "address": "2rKUvXu7WpfC9VyEvqwVVxxRVKqNp4CgXYwStmfiqqpFAkSC",
    },
    {
        "pub_key": b"008ebb52da3030f06e0c0c5f7d0fbacf6a22cedb1229bb4824a230fbe84bf89304",
        "version": b"\x02",
        "address": "FoTxsgYKH4AUngJAJNsqgmK85RzCc6cerkrsN18wiFfwBrn",
    },
    {
        "pub_key": b"e92b4b43a62fa66293f315486d66a67076e860e2aad76acb8e54f9bb7c925cd9",
        "version": b"\x2A",
        "address": "5HLRsimRtdb11HX73JtRd79avhCMruocgDJUXdosSJK1s6nz",
    },
    {
        "pub_key": b"2b0538c7c738a370385dc9404fbde697e29d1243d7d7f5c5e558bf4be738b82c",
        "version": b"\x2C",
        "address": "5QcRz3fyEiDawvuG6oyfZQ4YBvzDjENWsxoeiwuB1TLJLo5x",
    },
]


#
# Tests
#
class SubstrateAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], SubstrateAddr.EncodeKey(key_bytes, test["version"]))
            self.assertEqual(test["address"], SubstrateAddr.EncodeKey(Ed25519PublicKey(key_bytes), test["version"]))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, SubstrateAddr.EncodeKey, Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)), b"\x00")
        self.assertRaises(TypeError, SubstrateAddr.EncodeKey, Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_COMPR_PUB_KEY)), b"\x00")

        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, SubstrateAddr.EncodeKey, binascii.unhexlify(test), b"\x00")
