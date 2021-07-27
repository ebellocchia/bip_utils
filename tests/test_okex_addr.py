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
from bip_utils import OkexAddr, Secp256k1PublicKey
from .test_ecc import (
    TEST_VECT_SECP256K1_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03baf0b46095920af1a8c636cd9d9df37286190607d44ed82688f62c6c002acbc8",
        "address": "ex143pr24a30ml64mzgl74fhyuhrwg82y7vmyse7q",
    },
    {
        "pub_key": b"027bba228d456609587ce5d30f63443f421a3b187f6c53c53ba7626568a1025081",
        "address": "ex1hfh528h34asdtq7t3k7lhsvkhqc32hcypk3gyt",
    },
    {
        "pub_key": b"03ec14157c1bb62c6b8ce10b7379bee621a6f79735b950eaf125913a3da19bdaf9",
        "address": "ex170k75kvpj4urgs98nnlkhhfz90jrulfkq5k8rn",
    },
    {
        "pub_key": b"03b5f6bafd1656dbd1502b7d941d7bed5cfb2d1b479be9506e92752c96c5145965",
        "address": "ex1wj4nhg2k54aersyvjrgkv9js4sq74tajsg6zm0",
    },
    {
        "pub_key": b"03068feb64a09aee06eac40abfabd16574e78108948405cc566f175509e17ebb52",
        "address": "ex1ak63v55f8e765zqk3ucndrzvt29jdjtrkz33f2",
    },
]


#
# Tests
#
class OkexAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], OkexAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], OkexAddr.EncodeKey(Secp256k1PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, OkexAddr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, OkexAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, OkexAddr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY)
        self.assertRaises(TypeError, OkexAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, OkexAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, OkexAddr.EncodeKey, binascii.unhexlify(test))
