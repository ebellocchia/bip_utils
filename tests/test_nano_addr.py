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
from bip_utils import NanoAddr, Ed25519PublicKey, Ed25519Blake2bPublicKey, Nist256p1PublicKey, Secp256k1PublicKey
from .test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_ED25519_COMPR_PUB_KEY, TEST_SECP256K1_COMPR_PUB_KEY, TEST_NIST256P1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0063b14c2b966809da4b4f90c53ee12633be9f708cbd834eb24012f9306f3e8f4a",
        "address": "nano_1rxjbioset1bub7nz6879uikeexymxrashe5bts616qs83qmx5tcxoeox6ms",
    },
    {
        "pub_key": b"0089624c7666f0b8004df74ef749a96991bb602273b41fec38e7190fcd2ebcb5f9",
        "address": "nano_34d4bju8fw7r138zgmqqb8npm6fue1j99f1zxiwgg8ahsnqdsfhsr6dyoimk",
    },
    {
        "pub_key": b"006bfef755481c161fcd56c7b7902193528a36b117563793cf02a374455e983dcf",
        "address": "nano_1tzyyxcni91p5z8ofjxqk1is8nnc8trjgojqkh9i7aunaohbihghw4edxiqj",
    },
    {
        "pub_key": b"8f3330f2d62eb3232b4d23d67193d37d9c61678d12445cc68620e0f648456788",
        "address": "nano_35sm85sfedom6eontaypg8bx8zewe7mrt6k6dm5aea91ys66cswa9bw9bg5f",
    },
    {
        "pub_key": b"1594ba7eecada3f311d52d84bc462a8398f4aac71d252cd4db79e946d5511f0d",
        "address": "nano_17enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfwgzbact6",
    },
]


#
# Tests
#
class NanoAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], NanoAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], NanoAddr.EncodeKey(Ed25519Blake2bPublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, NanoAddr.EncodeKey, Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, NanoAddr.EncodeKey, Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, NanoAddr.EncodeKey, Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_COMPR_PUB_KEY)))

        # Test vector
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, NanoAddr.EncodeKey, binascii.unhexlify(test))
