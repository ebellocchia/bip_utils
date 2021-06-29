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
    Bip84BitcoinMainNet, Bip84BitcoinTestNet, Bip84LitecoinMainNet, Bip84LitecoinTestNet,
    P2WPKHAddr,
    Ed25519PublicKey, Nist256p1PublicKey, Secp256k1PublicKey
)
from .test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, TEST_ED25519_COMPR_PUB_KEY, TEST_NIST256P1_COMPR_PUB_KEY

# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        "wit_ver": 0,
        "net_ver": Bip84BitcoinMainNet.AddrConfKey("net_ver"),
    },
    {
        "pub_key": b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
        "address": "bc1qtet8q6cd5vqm0zjfcfm8mfsydju0a29ggqrmu9",
        "wit_ver": 0,
        "net_ver": Bip84BitcoinMainNet.AddrConfKey("net_ver"),
    },
    {
        "pub_key": b"021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17",
        "address": "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
        "wit_ver": 0,
        "net_ver": Bip84LitecoinMainNet.AddrConfKey("net_ver"),
    },
    {
        "pub_key": b"0201084ea04fa9619a056281e7c87a97693f67e5baa4ec604e7e8245b84e31cc96",
        "address": "ltc1qdjtr2jc5uu6r0ss2fcey3djvkhlu7jux420fhr",
        "wit_ver": 0,
        "net_ver": Bip84LitecoinMainNet.AddrConfKey("net_ver"),
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
        "address": "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
        "wit_ver": 0,
        "net_ver": Bip84BitcoinTestNet.AddrConfKey("net_ver"),
    },
    {
        "pub_key": b"03bb5db212192d5b428c5db726aba21426d0a63b7a453b0104f2398326bca43fc2",
        "address": "tltc1q677973lw0w796gttpy52f296jqaaksz0duklcr",
        "wit_ver": 0,
        "net_ver": Bip84LitecoinTestNet.AddrConfKey("net_ver"),
    },
]


#
# Tests
#
class P2WPKHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"],
                             P2WPKHAddr.EncodeKey(key_bytes, test["wit_ver"], test["net_ver"]))
            self.assertEqual(test["address"],
                             P2WPKHAddr.EncodeKey(Secp256k1PublicKey(key_bytes), test["wit_ver"], test["net_ver"]))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, P2WPKHAddr.EncodeKey, Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)))
        self.assertRaises(TypeError, P2WPKHAddr.EncodeKey, Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)))

        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, P2WPKHAddr.EncodeKey, binascii.unhexlify(test))
