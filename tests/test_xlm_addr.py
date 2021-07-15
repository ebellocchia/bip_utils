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
    XlmAddr,
    Ed25519PublicKey, Ed25519Blake2bPublicKey, Nist256p1PublicKey, Secp256k1PublicKey, Sr25519PublicKey
)
from .test_ecc import (
    TEST_VECT_ED25519_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"004342d377174aeabce717c67d66df8ba7a8f3835d3c6e978b8bdb63a444d2f6ab",
        "address": "GBBUFU3XC5FOVPHHC7DH2ZW7ROT2R44DLU6G5F4LRPNWHJCE2L3KWRPA",
    },
    {
        "pub_key": b"0073658385894c3c9f01a15e9f97d7d65f24d8f7bb1656bfe79a6f7512de132b68",
        "address": "GBZWLA4FRFGDZHYBUFPJ7F6X2ZPSJWHXXMLFNP7HTJXXKEW6CMVWQTNY",
    },
    {
        "pub_key": b"00eaf531f163a1e91da0a5dbb198fab8ec06b42296ceff584781c42f04eb1ba87c",
        "address": "GDVPKMPRMOQ6SHNAUXN3DGH2XDWANNBCS3HP6WCHQHCC6BHLDOUHZ25S",
    },
    {
        "pub_key": b"00eea5fe0eb96b032d0067fc35fd2c2579e408d437e8d6f9be9d3f9246f24f9b95",
        "address": "GDXKL7QOXFVQGLIAM76DL7JMEV46ICGUG7UNN6N6TU7ZERXSJ6NZLIGP",
    },
    {
        "pub_key": b"00046e316bc3207638f91823bb4822c6562e8aef15f3ce7e35df75f7bf6081fd81",
        "address": "GACG4MLLYMQHMOHZDAR3WSBCYZLC5CXPCXZ447RV3527PP3AQH6YCMW5",
    },
]


#
# Tests
#
class XlmAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], XlmAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], XlmAddr.EncodeKey(Ed25519PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, XlmAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, XlmAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, XlmAddr.EncodeKey, TEST_SECP256K1_PUB_KEY)
        self.assertRaises(TypeError, XlmAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, XlmAddr.EncodeKey, binascii.unhexlify(test))
