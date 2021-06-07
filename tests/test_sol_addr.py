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
from bip_utils import SolAddr, Ed25519PublicKey, Nist256p1PublicKey, Secp256k1PublicKey
from .test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_SECP256K1_COMPR_PUB_KEY, TEST_NIST256P1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547",
        "address": "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL",
    },
    {
        "pub_key": b"008b4564d4b6be05d6ead16d246c5e30773da9459040370284b57c944a3d0a1481",
        "address": "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi",
    },
    {
        "pub_key": b"00dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832",
        "address": "G5DnnAkA9jV3WZ25xh1Z6FcH3vtSyLi6p9nmPpr6dQMX",
    },
    {
        "pub_key": b"e54f392e5ffd3ca8802d3dbaa052667f82f8ff559a9cb23eda39cd386639c6ea",
        "address": "GS8RquhotKk9sDguxzjg5sJPM8RhfmKXWNEW61Jzjvvu",
    },
    {
        "pub_key": b"6031798a9f0f4939c3335d313848437fe72aefbe0d700de3268a2d45cebedc7c",
        "address": "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
    },
]


#
# Tests
#
class SolAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], SolAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], SolAddr.EncodeKey(Ed25519PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, SolAddr.EncodeKey, Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, SolAddr.EncodeKey, Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_COMPR_PUB_KEY)))

        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, SolAddr.EncodeKey, binascii.unhexlify(test))
