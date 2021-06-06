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
from bip_utils import BitcoinConf, LitecoinConf, P2WPKH, Ed25519PublicKey, Secp256k1PublicKey

# Some random public keys (verified with https://iancoleman.io/bip39/)
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        "net_addr_ver": BitcoinConf.P2WPKH_NET_VER.Main(),
    },
    {
        "pub_key": b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
        "address": "bc1qtet8q6cd5vqm0zjfcfm8mfsydju0a29ggqrmu9",
        "net_addr_ver": BitcoinConf.P2WPKH_NET_VER.Main(),
    },
    {
        "pub_key": b"021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17",
        "address": "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
        "net_addr_ver": LitecoinConf.P2WPKH_NET_VER.Main(),
    },
    {
        "pub_key": b"0201084ea04fa9619a056281e7c87a97693f67e5baa4ec604e7e8245b84e31cc96",
        "address": "ltc1qdjtr2jc5uu6r0ss2fcey3djvkhlu7jux420fhr",
        "net_addr_ver": LitecoinConf.P2WPKH_NET_VER.Main(),
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
        "address": "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
        "net_addr_ver": BitcoinConf.P2WPKH_NET_VER.Test(),
    },
    {
        "pub_key": b"03bb5db212192d5b428c5db726aba21426d0a63b7a453b0104f2398326bca43fc2",
        "address": "tltc1q677973lw0w796gttpy52f296jqaaksz0duklcr",
        "net_addr_ver": LitecoinConf.P2WPKH_NET_VER.Test(),
    },
]

# Tests for invalid keys
TEST_VECT_KEY_INVALID = [
    # Private key
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
    # Compressed public key with valid length but wrong version
    b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
    # Compressed public key with invalid length
    b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
    # Uncompressed public key with valid length but wrong version
    b"058ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
    # Uncompressed public key with invalid length
    b"04fd87569e9af6015d9d938c67c68fcdf5440d3c235eccbc1195a1924bba90e5e1954cb6d841054791ac227a8c11f79f77d24a20b238402c5424c8e436bb49",
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
                             P2WPKH.ToAddress(key_bytes, test["net_addr_ver"]))
            self.assertEqual(test["address"],
                             P2WPKH.ToAddress(Secp256k1PublicKey(key_bytes), test["net_addr_ver"]))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, P2WPKH.ToAddress, Ed25519PublicKey(b"000102030405060708090a0b0c0d0e0f"))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, P2WPKH.ToAddress, binascii.unhexlify(test))
