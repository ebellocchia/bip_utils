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
import binascii
import unittest

from bip_utils import (
    Bip32PrivateKey, Bip32PublicKey, CardanoShelleyPrivateKeys, CardanoShelleyPublicKeys, Cip1852Conf,
    EllipticCurveTypes
)
from bip_utils.bip.bip32.bip32_const import Bip32Const
from tests.bip.bip32.test_bip32_keys import TEST_BIP32_KEY_DATA


# Test vector
TEST_VECT = [
    {
        "staking": {
            "pub_key": "007bedc6ee43a5e3a4fb1b683e87adf312882be01367d387318e91b0fdcd603af7",
            "priv_key": "e08c70733d0b31968411743f1238bc7a642640a3f6f2e2922a07f7ddbde41c47c5af85fed47bdca0df5b36c22ae7be47b9478f6c478c34e3d524feb14941b347",
            "address": "stake1u9cypgkgzlknjktakdemm73p49k5rtyqznwra3p0h8rxwtg0vjunm",
        },
        "address": {
            "pub_key": "0053011f62ec32fc67066cec3ea3c697c5f70f09ca505c174368d2c890672a2af5",
            "priv_key": "f0c2517d8ba8efe38684bf92bc383fbf63974a9c917e5c373b29b07bbfe41c47e6333853939c9c0e5a608e4dab1c38c80759347824e979dd6122300e50e1c934",
            "address": "addr1q9ug2zur0nmy0pwjk023cnzxlru6vc3rw67r9qlsufjg5rtsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksx5aka8",
        },
    },
    {
        "staking": {
            "pub_key": "00a22d0b8709e6bc04d11257dc405410d1ace01f207c391ba4788ea17198ee1a08",
            "priv_key": "305969fa551be3ef077cca781aaa0794207207048e9c6172de14ceec5246204c15f15c6367cc79b590d37d50acd3edb5507e5f1044289e9532f95e262c1bff71",
            "address": "stake1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8squng76",
        },
        "address": {
            "pub_key": "00943c9cd23dfecaefde516e9774dd3a1f5c4aa58b0d68b4dd08f88965a58b7db7",
            "priv_key": "c05f39f4260bc1673d6af1808c9be07e9d0b8fee482072baa77a0f7e5046204c1f88e23f7024e87bed00ff5b57f0d55b54dabd886f684c06cb39c4c626dfa705",
            "address": "addr1q85q038lxyc2dftwxqt80fgxm49h2l8pya7s9cvrvx6478xr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qg9enpz",
        },
    },
]


#
# Tests
#
class CardanoShelleyKeysTests(unittest.TestCase):
    # Test private key
    def test_priv_key(self):
        for test in TEST_VECT:
            addr_key = self.__create_priv_key(test["address"]["priv_key"])
            sk_key = self.__create_priv_key(test["staking"]["priv_key"])
            self.__test_priv_key(
                CardanoShelleyPrivateKeys(addr_key, sk_key, Cip1852Conf.CardanoIcarusMainNet),
                test,
            )

    # Test public key
    def test_pub_key(self):
        for test in TEST_VECT:
            addr_key = self.__create_pub_key(test["address"]["pub_key"])
            sk_key = self.__create_pub_key(test["staking"]["pub_key"])
            self.__test_pub_key(
                CardanoShelleyPublicKeys(addr_key, sk_key, Cip1852Conf.CardanoIcarusMainNet),
                test
            )

    # Test private key
    def __test_priv_key(self, shelley_key, test):
        # Objects
        self.assertTrue(isinstance(shelley_key.AddressKey(), Bip32PrivateKey))
        self.assertTrue(isinstance(shelley_key.RewardKey(), Bip32PrivateKey))
        self.assertTrue(isinstance(shelley_key.StakingKey(), Bip32PrivateKey))
        # RewardKey
        self.assertTrue(shelley_key.RewardKey() is shelley_key.StakingKey())
        # Keys
        self.assertEqual(test["address"]["priv_key"], shelley_key.AddressKey().Raw().ToHex())
        self.assertEqual(test["staking"]["priv_key"], shelley_key.StakingKey().Raw().ToHex())
        # Public key associated to the private one
        self.__test_pub_key(shelley_key.PublicKeys(), test)

    # Test public key
    def __test_pub_key(self, shelley_key, test):
        # Objects
        self.assertTrue(isinstance(shelley_key.AddressKey(), Bip32PublicKey))
        self.assertTrue(isinstance(shelley_key.RewardKey(), Bip32PublicKey))
        self.assertTrue(isinstance(shelley_key.StakingKey(), Bip32PublicKey))
        # RewardKey
        self.assertTrue(shelley_key.RewardKey() is shelley_key.StakingKey())
        # Keys
        self.assertEqual(test["address"]["pub_key"], shelley_key.AddressKey().RawCompressed().ToHex())
        self.assertEqual(test["staking"]["pub_key"], shelley_key.StakingKey().RawCompressed().ToHex())
        # Address
        self.assertEqual(test["address"]["address"], shelley_key.ToAddress())
        self.assertEqual(test["staking"]["address"], shelley_key.ToRewardAddress())
        self.assertEqual(test["staking"]["address"], shelley_key.ToStakingAddress())

    # Create private key
    def __create_priv_key(self, key_bytes):
        return Bip32PrivateKey.FromBytesOrKeyObject(
            binascii.unhexlify(key_bytes), TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, EllipticCurveTypes.ED25519_KHOLAW
        )

    # Create public key
    def __create_pub_key(self, key_bytes):
        return Bip32PublicKey.FromBytesOrKeyObject(
            binascii.unhexlify(key_bytes), TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, EllipticCurveTypes.ED25519_KHOLAW
        )
