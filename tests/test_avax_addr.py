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
    AvaxPChainAddr, AvaxXChainAddr,
    Ed25519PublicKey, Ed25519Blake2bPublicKey, Nist256p1PublicKey, Secp256k1PublicKey, Sr25519PublicKey
)
from .test_ecc import (
    TEST_VECT_SECP256K1_PUB_KEY_INVALID,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_NIST256P1_PUB_KEY, TEST_SR25519_PUB_KEY
)

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"02add530ea489143b936d2430e8412182984cdb26c020ce18ddc34dbf24a442b7d",
        "chain": "X",
        "address": "X-avax123ghjvxx49h87g0vk26c97ca8x3v44g5n9mzha",
    },
    {
        "pub_key": b"03465789245ff8a454efc9a72608521f30bcc49e35f1bf26272d0a6cb7a7b91876",
        "chain": "X",
        "address": "X-avax164klxn22zr2g4q4m3k03zy8skrpgrt36sqm5r4",
    },
    {
        "pub_key": b"03a90de501b386356e40d9800431f06698241414590498903b80f0aeb184dfa537",
        "chain": "P",
        "address": "P-avax14q4ugdl65sagjx4as20fuqf37ecaeadcqm96zt",
    },
    {
        "pub_key": b"0317e4b698b4e370ced9fec7c02bfd5c56055e07db49fdc623b1545eb7a61a1287",
        "chain": "P",
        "address": "P-avax1e4wshkjvqpfcuu86acl69xad8sl7zsgg723xu3",
    },
]


#
# Tests
#
class AvaxAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            addr_cls = AvaxXChainAddr if test["chain"] == "X" else AvaxPChainAddr
            self.assertEqual(test["address"], addr_cls.EncodeKey(key_bytes))
            self.assertEqual(test["address"], addr_cls.EncodeKey(Secp256k1PublicKey.FromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key types
        self.assertRaises(TypeError, AvaxPChainAddr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, AvaxPChainAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, AvaxPChainAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, AvaxPChainAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        self.assertRaises(TypeError, AvaxXChainAddr.EncodeKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, AvaxXChainAddr.EncodeKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, AvaxXChainAddr.EncodeKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, AvaxXChainAddr.EncodeKey, TEST_SR25519_PUB_KEY)

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, AvaxPChainAddr.EncodeKey, binascii.unhexlify(test))
            self.assertRaises(ValueError, AvaxXChainAddr.EncodeKey, binascii.unhexlify(test))
