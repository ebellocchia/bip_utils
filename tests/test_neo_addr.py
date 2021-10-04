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
from bip_utils import NeoAddr, Nist256p1PublicKey
from .test_ecc import (
    TEST_VECT_NIST256P1_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
    TEST_SECP256K1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03f4890a76acd4ec68537f1bfb5ed18121126babda24f65b6488e2ac57cf9becce",
        "version": b"\x17",
        "address": "AcLDSGFoA3Re71QFF8nkpH31EoQjhoApkY",
    },
    {
        "pub_key": b"0217a644d0278b30015a15f363eae4c8ea7e619c234bc8be2accac531c2817e7d1",
        "version": b"\x17",
        "address": "AQos7r7repyb9AUzFuKc8voH4TS9XuQg7H",
    },
    {
        "pub_key": b"03e43cbeea55520fbd8e79b02a7e2ff5ddd881ac3f3603cb48d08423317b805831",
        "version": b"\x17",
        "address": "AR3UZwqfjzvDuqUHwtdcGREqDSqpB3HDoP",
    },
    {
        "pub_key": b"02c23193a2ae86390b61ccae1302c4e3cfc3429b6d74282de13a368e8dbedbf50e",
        "version": b"\x17",
        "address": "AUYShq2btNbP1qG4jeN1sBnzu2wv2EdvxF",
    },
    {
        "pub_key": b"02db975db10d75b3581945fb5e2b3d99e27ed2c50a9f2de19f2ec2a878fc4d9901",
        "version": b"\x17",
        "address": "AMJm3XvdgZdHMK4T8XsWxKbrnPbTAC5ka7",
    },
]


#
# Tests
#
class NeoAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], NeoAddr.EncodeKey(key_bytes,
                                                                ver=test["version"]))
            self.assertEqual(test["address"], NeoAddr.EncodeKey(Nist256p1PublicKey.FromBytes(key_bytes),
                                                                ver=test["version"]))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, NeoAddr.EncodeKey, TEST_ED25519_PUB_KEY, ver=b"")
        self.assertRaises(TypeError, NeoAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY, ver=b"")
        self.assertRaises(TypeError, NeoAddr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY, ver=b"")
        self.assertRaises(TypeError, NeoAddr.EncodeKey, TEST_SECP256K1_PUB_KEY, ver=b"")
        self.assertRaises(TypeError, NeoAddr.EncodeKey, TEST_SR25519_PUB_KEY, ver=b"")

        # Test vector
        for test in TEST_VECT_NIST256P1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, NeoAddr.EncodeKey, binascii.unhexlify(test), ver=b"")
