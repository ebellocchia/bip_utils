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
from bip_utils import FilSecp256k1Addr, Secp256k1PublicKey
from .test_ecc import (
    TEST_VECT_SECP256K1_PUB_KEY_INVALID, TEST_SECP256K1_PUB_KEY,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0258742e7596b2cb998b42dddffd7b5c7ba30702876f899d6f7188d23285fc3208",
        "address": "f1hqdqidehi276cscqehffoyr7qzxn2foumjpq5zq",
    },
    {
        "pub_key": b"03ad9c631c2fac4adca03c1abf9e473dc9bd6dca7868e6b961ebb81547819c6e8c",
        "address": "f1wp33qygxrlon4axdhim5cqlyfpv75wokvcfdgyy",
    },
    {
        "pub_key": b"036d34f7fde5eedcea7c35e59112abee4786190cec263469b8a92fa15222999cff",
        "address": "f1txp5wggfletonal5ivc4dcdkgcsipwg4fte42wi",
    },
    {
        "pub_key": b"03560c22685ce5837b897bd553a4e23af0bf464ef72ddbb32d252d1fbcec4f8c81",
        "address": "f1k3gidardziywl37nbnfwad6eaeomq74xwcs2wxq",
    },
    {
        "pub_key": b"021e8c1330274bd99ba01e019f2cbe07e8822f8b8919f4c1cb38d389903d67f158",
        "address": "f1m24kgttzcfhdbrwy7fxljbuhrl6dtdcqhy4xnla",
    },
]


#
# Tests
#
class FilAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], FilSecp256k1Addr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], FilSecp256k1Addr.EncodeKey(Secp256k1PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, FilSecp256k1Addr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, FilSecp256k1Addr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, FilSecp256k1Addr.EncodeKey, TEST_ED25519_MONERO_PUB_KEY)
        self.assertRaises(TypeError, FilSecp256k1Addr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, FilSecp256k1Addr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, FilSecp256k1Addr.EncodeKey, binascii.unhexlify(test))
