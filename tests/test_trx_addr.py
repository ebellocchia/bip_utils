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
    TrxAddr,
    Ed25519PublicKey, Ed25519Blake2bPublicKey, Nist256p1PublicKey, Secp256k1PublicKey, Sr25519PublicKey
)
from .test_ecc import (
    TEST_VECT_SECP256K1_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_NIST256P1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"033d77bf3f63edd7aad3163c6f04eb48e968a76c3043def375c21a8414675e11ae",
        "address": "TDvr6Jpwfp1wDiV7PhaB19YMsMHRSXmY7p",
    },
    {
        "pub_key": b"03436c3e77f7738dcbfc2cfbb6e12e1509979cde41f216eed86c82ab661b5b3fc0",
        "address": "TXJ2Z9VAwDpQ4W6zwTpXxRUpwFVDetPQuC",
    },
    {
        "pub_key": b"02f6cd3a2761360cd7e8c183aca501ee0ce0e42fc270a68aafd153dd06c857a8c4",
        "address": "TNdfXv6WTTyS2ohkTu8YA62WmLTNWqK46i",
    },
    {
        "pub_key": b"0360e11323f918ade5a53bd5ac7171712f019f62e9ad8e0e18ec2b8ca01d4daba4",
        "address": "TF7cowibxyJdMyGtjP2yP7oyN5ZmSMPnWd",
    },
    {
        "pub_key": b"034767fb943ddb893377754ba71e4f82ec15134c7fe4240529d3d0ff473650b210",
        "address": "TYQPvAG6AuzQed8RPuH62pcbZBKj9TkPk1",
    },
]


#
# Tests
#
class TrxAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], TrxAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], TrxAddr.EncodeKey(Secp256k1PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, TrxAddr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, TrxAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, TrxAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, TrxAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, TrxAddr.EncodeKey, binascii.unhexlify(test))
