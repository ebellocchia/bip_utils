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
from bip_utils import (
    SubstrateEd25519Addr, SubstrateSr25519Addr,
    Ed25519PublicKey, Sr25519PublicKey
)
from .test_ecc import (
    TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_VECT_SR25519_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
        "ss58_format": 0,
        "address": "12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU",
    },
    {
        "pub_key": b"00e8474b9c29d44d45c0755077d4f8a21dc611c76e36e261773b5410b8e5bf15a1",
        "ss58_format": 7,
        "address": "nmB6fx6ehzHwA4wyfFVZig28cCAcathGwfShrNsvueitzZC",
    },
    {
        "pub_key": b"008b4564d4b6be05d6ead16d246c5e30773da9459040370284b57c944a3d0a1481",
        "ss58_format": 18,
        "address": "2rKUvXu7WpfC9VyEvqwVVxxRVKqNp4CgXYwStmfiqqpFAkSC",
    },
    {
        "pub_key": b"008ebb52da3030f06e0c0c5f7d0fbacf6a22cedb1229bb4824a230fbe84bf89304",
        "ss58_format": 2,
        "address": "FoTxsgYKH4AUngJAJNsqgmK85RzCc6cerkrsN18wiFfwBrn",
    },
    {
        "pub_key": b"e92b4b43a62fa66293f315486d66a67076e860e2aad76acb8e54f9bb7c925cd9",
        "ss58_format": 42,
        "address": "5HLRsimRtdb11HX73JtRd79avhCMruocgDJUXdosSJK1s6nz",
    },
    {
        "pub_key": b"2b0538c7c738a370385dc9404fbde697e29d1243d7d7f5c5e558bf4be738b82c",
        "ss58_format": 70,
        "address": "ctpqudSL8v7QCi3dVRZkBK55i6JGLQuyCAxqFsTho4DCMmw87",
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
            self.assertEqual(test["address"], SubstrateEd25519Addr.EncodeKey(key_bytes,
                                                                             ss58_format=test["ss58_format"]))
            self.assertEqual(test["address"], SubstrateEd25519Addr.EncodeKey(Ed25519PublicKey.FromBytes(key_bytes),
                                                                             ss58_format=test["ss58_format"]))

            # Remove prefix
            key_bytes = key_bytes[1:] if len(key_bytes) == 33 else key_bytes
            self.assertEqual(test["address"], SubstrateSr25519Addr.EncodeKey(key_bytes,
                                                                             ss58_format=test["ss58_format"]))
            self.assertEqual(test["address"], SubstrateSr25519Addr.EncodeKey(Sr25519PublicKey.FromBytes(key_bytes),
                                                                             ss58_format=test["ss58_format"]))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, SubstrateEd25519Addr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateEd25519Addr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateEd25519Addr.EncodeKey, TEST_NIST256P1_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateEd25519Addr.EncodeKey, TEST_SECP256K1_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateEd25519Addr.EncodeKey, TEST_SR25519_PUB_KEY, ss58_format=0)

        self.assertRaises(TypeError, SubstrateSr25519Addr.EncodeKey, TEST_ED25519_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateSr25519Addr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateSr25519Addr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateSr25519Addr.EncodeKey, TEST_NIST256P1_PUB_KEY, ss58_format=0)
        self.assertRaises(TypeError, SubstrateSr25519Addr.EncodeKey, TEST_SECP256K1_PUB_KEY, ss58_format=0)

        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, SubstrateEd25519Addr.EncodeKey, binascii.unhexlify(test), ss58_format=0)

        # Test vector
        for test in TEST_VECT_SR25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, SubstrateSr25519Addr.EncodeKey, binascii.unhexlify(test), ss58_format=0)
