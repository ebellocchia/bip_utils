# Copyright (c) 2022 Emanuele Bellocchia
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
    Bip32PrivateKey, Bip32PublicKey, Bip44Conf, Bip44PrivateKey, Bip44PublicKey, Cip1852Coins, Cip1852ConfGetter,
    DataBytes
)
from bip_utils.bip.bip32.bip32_const import Bip32Const
from tests.bip.bip32.test_bip32_keys import TEST_BIP32_KEY_DATA
from tests.ecc.test_ecc import (
    TEST_ED25519_BLAKE2B_PRIV_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_KHOLAW_PRIV_KEY,
    TEST_ED25519_KHOLAW_PUB_KEY, TEST_ED25519_PRIV_KEY, TEST_ED25519_PUB_KEY, TEST_NIST256P1_PRIV_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PRIV_KEY, TEST_SECP256K1_PUB_KEY
)


# Public keys for testing
TEST_PUB_KEYS = [
    {
        "key": TEST_ED25519_PUB_KEY,
        "conf": Bip44Conf.Algorand,
        "address": "PVPKAOVRKALJC5XWNX3PN5T27ZYLJWPIWBX2NNDM25F2WHFF45ODDRMTMA",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PUB_KEY,
        "conf": Bip44Conf.Nano,
        "address": "nano_3kw895nbxskizqabuixm8inn3sb7m4r8wgqr4pdng8iagsargo6jbrca19fr",
    },
    {
        "key": TEST_ED25519_KHOLAW_PUB_KEY,
        "conf": Bip44Conf.CardanoByronIcarus,
        "address": "Ae2tdPwUPEZ8AFZwGqwVWNY2x6rDEmQVx6izy5NtBYqEPp6LTu98Fy3SgsA",
    },
    {
        "key": TEST_NIST256P1_PUB_KEY,
        "conf": Bip44Conf.Neo,
        "address": "AMBkJJRc9CsdSLdxqX3FPK6aQe7cTuAVjo",
    },
    {
        "key": TEST_SECP256K1_PUB_KEY,
        "conf": Bip44Conf.BitcoinMainNet,
        "address": "1MYrWmM3MQtMt8jwf9kLeHnVxnC59rFWK3",
    },
]

# Private keys for testing
TEST_PRIV_KEYS = [
    {
        "key": TEST_ED25519_PRIV_KEY,
        "conf": Bip44Conf.Algorand,
        "wif": "",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PRIV_KEY,
        "conf": Bip44Conf.Nano,
        "wif": "",
    },
    {
        "key": TEST_ED25519_KHOLAW_PRIV_KEY,
        "conf": Bip44Conf.CardanoByronIcarus,
        "wif": "",
    },
    {
        "key": TEST_NIST256P1_PRIV_KEY,
        "conf": Bip44Conf.Neo,
        "wif": "",
    },
    {
        "key": TEST_SECP256K1_PRIV_KEY,
        "conf": Bip44Conf.BitcoinMainNet,
        "wif": "L4ngnZNFoErog8jR28jQj8ByPW5vkttUA6GnE4pcZpBzYoVzu1n8",
    },
]

# BIP32 public key for testing
TEST_BIP32_PUB_KEY = Bip32PublicKey.FromBytesOrKeyObject(
    TEST_SECP256K1_PUB_KEY, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, TEST_SECP256K1_PUB_KEY.CurveType()
)
# BIP32 private key for testing
TEST_BIP32_PRIV_KEY = Bip32PrivateKey.FromBytesOrKeyObject(
    TEST_SECP256K1_PRIV_KEY, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, TEST_SECP256K1_PRIV_KEY.CurveType()
)


#
# Tests
#
class Bip44KeyDataTests(unittest.TestCase):
    # Test private key
    def test_priv_key(self):
        for i, test in enumerate(TEST_PRIV_KEYS):
            bip32_key = Bip32PrivateKey.FromBytesOrKeyObject(
                test["key"], TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, test["key"].CurveType()
            )
            bip44_key = Bip44PrivateKey(bip32_key, test["conf"])
            self.__test_priv_key_obj(bip44_key, bip32_key, test, TEST_PUB_KEYS[i])

    # Test public key
    def test_pub_key(self):
        for test in TEST_PUB_KEYS:
            bip32_key = Bip32PublicKey.FromBytesOrKeyObject(
                test["key"], TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, test["key"].CurveType()
            )
            bip44_key = Bip44PublicKey(bip32_key, test["conf"])
            self.__test_pub_key_obj(bip44_key, bip32_key, test)

    # Test invalid params
    def test_invalid_params(self):
        # Different elliptic curve between BIP32 key and coin configuration
        self.assertRaises(ValueError, Bip44PublicKey, TEST_BIP32_PUB_KEY, Bip44Conf.Neo)
        self.assertRaises(ValueError, Bip44PrivateKey, TEST_BIP32_PRIV_KEY, Bip44Conf.Neo)

    # Test forbidden address classes
    def test_forbidden_addr_cls(self):
        # Cardano
        bip32_key = Bip32PublicKey.FromBytesOrKeyObject(
            TEST_ED25519_KHOLAW_PUB_KEY, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, TEST_ED25519_KHOLAW_PUB_KEY.CurveType()
        )
        for cip_coin in Cip1852Coins:
            self.assertRaises(ValueError, Bip44PublicKey(bip32_key, Cip1852ConfGetter.GetConfig(cip_coin)).ToAddress)

        # Monero (ed25519)
        bip32_key = Bip32PublicKey.FromBytesOrKeyObject(
            TEST_ED25519_PUB_KEY, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, TEST_ED25519_PUB_KEY.CurveType()
        )
        self.assertRaises(ValueError, Bip44PublicKey(bip32_key, Bip44Conf.MoneroEd25519Slip).ToAddress)
        # Monero (secp256k1)
        bip32_key = Bip32PublicKey.FromBytesOrKeyObject(
            TEST_SECP256K1_PUB_KEY, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, TEST_SECP256K1_PUB_KEY.CurveType()
        )
        self.assertRaises(ValueError, Bip44PublicKey(bip32_key, Bip44Conf.MoneroSecp256k1).ToAddress)

    # Test private key object
    def __test_priv_key_obj(self, bip44_key, bip32_key, test, test_pub_key):
        # Objects
        self.assertTrue(isinstance(bip44_key.Bip32Key(), Bip32PrivateKey))
        self.assertTrue(isinstance(bip44_key.Raw(), DataBytes))
        self.assertTrue(isinstance(bip44_key.PublicKey(), Bip44PublicKey))
        # BIP32 key
        self.assertTrue(bip44_key.Bip32Key() is bip32_key)
        # Chain code
        self.assertEqual(bip44_key.ChainCode(), bip32_key.Data().ChainCode())
        # Keys
        self.assertEqual(bip44_key.ToExtended(), bip32_key.ToExtended())
        self.assertEqual(bip44_key.Raw().ToBytes(), bip32_key.Raw().ToBytes())
        # WIF
        self.assertEqual(bip44_key.ToWif(), test["wif"])
        # Test public key
        self.__test_pub_key_obj(bip44_key.PublicKey(), bip32_key.PublicKey(), test_pub_key)

    # Test public key object
    def __test_pub_key_obj(self, bip44_key, bip32_key, test):
        # Object
        self.assertTrue(isinstance(bip44_key.Bip32Key(), Bip32PublicKey))
        self.assertTrue(isinstance(bip44_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(bip44_key.RawUncompressed(), DataBytes))
        # BIP32 key
        self.assertTrue(bip44_key.Bip32Key() is bip32_key)
        # Chain code
        self.assertEqual(bip44_key.ChainCode(), bip32_key.Data().ChainCode())
        # Keys
        self.assertEqual(bip44_key.ToExtended(), bip32_key.ToExtended())
        self.assertEqual(bip44_key.RawCompressed().ToBytes(), bip32_key.RawCompressed().ToBytes())
        self.assertEqual(bip44_key.RawUncompressed().ToBytes(), bip32_key.RawUncompressed().ToBytes())
        # Address
        self.assertEqual(bip44_key.ToAddress(), test["address"])
