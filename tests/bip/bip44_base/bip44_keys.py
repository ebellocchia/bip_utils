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
import unittest
from bip_utils import (
    Bip44Algorand, Bip44BitcoinMainNet, Bip44Nano, Bip44Neo,
    Bip32PublicKey, Bip32PrivateKey, Bip44PublicKey, Bip44PrivateKey
)
from tests.bip.bip32.test_bip32_keys import TEST_KEY_DATA
from tests.ecc.test_ecc import (
    TEST_ED25519_PRIV_KEY, TEST_ED25519_BLAKE2B_PRIV_KEY, TEST_NIST256P1_PRIV_KEY, TEST_SECP256K1_PRIV_KEY,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PUB_KEY
)

# Public keys for testing
TEST_PUB_KEYS = [
    {
        "key": TEST_ED25519_PUB_KEY,
        "conf": Bip44Algorand,
        "address": "PVPKAOVRKALJC5XWNX3PN5T27ZYLJWPIWBX2NNDM25F2WHFF45ODDRMTMA",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PUB_KEY,
        "conf": Bip44Nano,
        "key_id": b"23e1ef48982188655152d7e651b754e562eb018e",
        "address": "nano_3kw895nbxskizqabuixm8inn3sb7m4r8wgqr4pdng8iagsargo6jbrca19fr",
    },
    {
        "key": TEST_NIST256P1_PUB_KEY,
        "conf": Bip44Neo,
        "address": "AMBkJJRc9CsdSLdxqX3FPK6aQe7cTuAVjo",
    },
    {
        "key": TEST_SECP256K1_PUB_KEY,
        "conf": Bip44BitcoinMainNet,
        "address": "1MYrWmM3MQtMt8jwf9kLeHnVxnC59rFWK3",
    },
]

# Private keys for testing
TEST_PRIV_KEYS = [
    {
        "key": TEST_ED25519_PRIV_KEY,
        "conf": Bip44Algorand,
        "wif": "",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PRIV_KEY,
        "conf": Bip44Nano,
        "key_id": b"23e1ef48982188655152d7e651b754e562eb018e",
        "wif": "",
    },
    {
        "key": TEST_NIST256P1_PRIV_KEY,
        "conf": Bip44Neo,
        "wif": "",
    },
    {
        "key": TEST_SECP256K1_PRIV_KEY,
        "conf": Bip44BitcoinMainNet,
        "wif": "L4ngnZNFoErog8jR28jQj8ByPW5vkttUA6GnE4pcZpBzYoVzu1n8",
    },
]

# BIP32 public key for testing
TEST_BIP32_PUB_KEY = Bip32PublicKey.FromBytesOrKeyObject(TEST_SECP256K1_PUB_KEY, TEST_KEY_DATA, TEST_SECP256K1_PUB_KEY.CurveType())
# BIP32 private key for testing
TEST_BIP32_PRIV_KEY = Bip32PrivateKey.FromBytesOrKeyObject(TEST_SECP256K1_PRIV_KEY, TEST_KEY_DATA, TEST_SECP256K1_PRIV_KEY.CurveType())


#
# Tests
#
class Bip44KeyDataTests(unittest.TestCase):
    # Test private key
    def test_priv_key(self):
        for test in TEST_PRIV_KEYS:
            bip32_key = Bip32PrivateKey.FromBytesOrKeyObject(test["key"], TEST_KEY_DATA, test["key"].CurveType())
            bip44_key = Bip44PrivateKey(bip32_key, test["conf"])

            self.assertTrue(bip44_key.Bip32Key() is bip32_key)
            self.assertEqual(bip44_key.ToExtended(), bip32_key.ToExtended())
            self.assertEqual(bip44_key.Raw().ToBytes(), bip32_key.Raw().ToBytes())
            self.assertEqual(bip44_key.ToWif(), test["wif"])

    # Test public key
    def test_pub_key(self):
        for test in TEST_PUB_KEYS:
            bip32_key = Bip32PublicKey.FromBytesOrKeyObject(test["key"], TEST_KEY_DATA, test["key"].CurveType())
            bip44_key = Bip44PublicKey(bip32_key, test["conf"])

            self.assertTrue(bip44_key.Bip32Key() is bip32_key)
            self.assertEqual(bip44_key.ToExtended(), bip32_key.ToExtended())
            self.assertEqual(bip44_key.RawCompressed().ToBytes(), bip32_key.RawCompressed().ToBytes())
            self.assertEqual(bip44_key.RawUncompressed().ToBytes(), bip32_key.RawUncompressed().ToBytes())
            self.assertEqual(bip44_key.ToAddress(), test["address"])

    # Test invalid params
    def test_invalid_params(self):
        # Different elliptic curve between BIP32 key and coin configuration
        self.assertRaises(ValueError, Bip44PublicKey, TEST_BIP32_PUB_KEY, Bip44Neo)
        self.assertRaises(ValueError, Bip44PrivateKey, TEST_BIP32_PRIV_KEY, Bip44Neo)
