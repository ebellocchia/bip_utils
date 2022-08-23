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
    Bip44, Bip44Changes, Bip44Coins, CardanoShelley, CardanoShelleyPrivateKeys, CardanoShelleyPublicKeys, Cip1852,
    Cip1852Coins
)


# Test vector
TEST_VECT = [
    {
        "coin": Cip1852Coins.CARDANO_ICARUS,
        "ex_acc": "xprv3ST19gxjCZJ9V1B7nA9eTu8aE8R7EZWZv6BUSL75hhYuUMwrEwn3icxmLJz8YFpzhBUNGPjJLGxdxhryMefD1Duex8sNR6KzRBnJN66jTeiPEAKcohdauX95tmRXfMrtaPegqZKVUTZkabvNNwF6gDz",
        "staking": {
            "pub_key": "00a22d0b8709e6bc04d11257dc405410d1ace01f207c391ba4788ea17198ee1a08",
            "priv_key": "305969fa551be3ef077cca781aaa0794207207048e9c6172de14ceec5246204c15f15c6367cc79b590d37d50acd3edb5507e5f1044289e9532f95e262c1bff71",
            "address": "stake1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8squng76",
        },
        "account": {
            "pub_key": "0062def90b803d2c5616165ac40db911b98261bdc2c2a9678a0a3837024fa2f998",
            "priv_key": "780de6f67db8e048fe17df60d1fff06dd700cc54b10fc4bcf30f59444d46204c0b890d7dce4c8142d4a4e8e26beac26d6f3c191a80d7b79cc5952968ad7ffbb7",
        },
        "change": {
            "pub_key": "005d2578308085af78f76d6afbd927ff869ed3ca74bfc29999e0f9f6fd665f869b",
            "priv_key": "a0ade21934608432561fabd52ca8076a6c8c9a94aeb984c6a6a94f074e46204c1a5091c16d4c7cdc4a6911da846b2c17030f8ba3451ef8315291a996e75921be",
        },
        "addresses": [
            {
                "pub_key": "00ba828d0ecbeb7e930351e2deada39323bfad7dfe14ee8a353630b7a2bc627486",
                "priv_key": "20627b6555f63793b43c37b33015b097cf54a0735487d09b95c8b4e44e46204cbc75383224dc49ee9530e582b6f774b9e366124c47575a87618f9d01b0760783",
                "address": "addr1qxz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969y7r3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0q8eqdws",
            },
            {
                "pub_key": "00bea13cd6ec6af14df076e107801bfe57187dca138ba503d1fbd7e135cb0b5e95",
                "priv_key": "c81b47af288ca8746776eb370b33fd3eb78cd42261e847d1590235754f46204c3dbaab4078f00d3cd15fd36e8fe07381af1fbbc5a8774823cd01131c8c1749b7",
                "address": "addr1qyg8whf7u4sjlw0fjapgyf6jzayx7svd9xqsv6thymk7s3kr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0quke8qu",
            },
            {
                "pub_key": "00943c9cd23dfecaefde516e9774dd3a1f5c4aa58b0d68b4dd08f88965a58b7db7",
                "priv_key": "c05f39f4260bc1673d6af1808c9be07e9d0b8fee482072baa77a0f7e5046204c1f88e23f7024e87bed00ff5b57f0d55b54dabd886f684c06cb39c4c626dfa705",
                "address": "addr1q85q038lxyc2dftwxqt80fgxm49h2l8pya7s9cvrvx6478xr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qg9enpz",
            },
        ],
    },
    {
        "coin": Cip1852Coins.CARDANO_LEDGER,
        "ex_acc": "xprv3S3na3DSNqpBEAQz1QxjyGH5mwJHfzXYY7HPr8VdrDtXUjDDWtfpyb1qKZpPDXCVfLFrhkNgXGVbReWhq4MXF2AbfyGCBGB4DnSFAwDm7GUhVHcTw1321bEMC1ameCUhGg1x1WcHMRM3q34GizJ2deS",
        "staking": {
            "pub_key": "007bedc6ee43a5e3a4fb1b683e87adf312882be01367d387318e91b0fdcd603af7",
            "priv_key": "e08c70733d0b31968411743f1238bc7a642640a3f6f2e2922a07f7ddbde41c47c5af85fed47bdca0df5b36c22ae7be47b9478f6c478c34e3d524feb14941b347",
            "address": "stake1u9cypgkgzlknjktakdemm73p49k5rtyqznwra3p0h8rxwtg0vjunm",
        },
        "account": {
            "pub_key": "006d587af152f01c6095904dc3c5d710d05b69dd2c6af244a367a9a72e5d8e8191",
            "priv_key": "509ee6767e649018fc70116acd808eb11b6059bd79f8e148d2b410c7b4e41c47742712638f5b39e4ace3e16fca72293aed6aee63597adb333f0f4b88533d3b95",
        },
        "change": {
            "pub_key": "00c759c86c873c5cef4cc928b338a6eeecd3c4b80fcf395d485f75d141ee210ab3",
            "priv_key": "e0e597d4eba82e14a9244a7cc5d52bb43ce1b5dfad9e58edcea51192b8e41c473984f12d39c592d0b8b25c1160e9374dcf4698bdfdc70e2191c1e558139b99e5",
        },
        "addresses": [
            {
                "pub_key": "0053011f62ec32fc67066cec3ea3c697c5f70f09ca505c174368d2c890672a2af5",
                "priv_key": "f0c2517d8ba8efe38684bf92bc383fbf63974a9c917e5c373b29b07bbfe41c47e6333853939c9c0e5a608e4dab1c38c80759347824e979dd6122300e50e1c934",
                "address": "addr1q9ug2zur0nmy0pwjk023cnzxlru6vc3rw67r9qlsufjg5rtsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksx5aka8",
            },
            {
                "pub_key": "00d1209e63903fff2baba027bcfb6c9b0d23d7f6889e00d7a6b3fc9d7456171b28",
                "priv_key": "806bb525081ada2f2e2a1ea4adfe1e35043420748e2f5bf1027f5d43bbe41c474730c109cdbf89f5446643189c9a0aa2343ff1959fd16665f835dada3425bf4e",
                "address": "addr1qx6yq2qe4cje59azajeg3eqzh79kglps5qq5xmx9pdu2mctsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksvyxuuh",
            },
            {
                "pub_key": "00b9b4e70e55021937099e6bea3a3d31bc66122642c03c4041b84b9caa3e0e944d",
                "priv_key": "4884c57fc14fcfe199c42b914ea0c6032999f30da1bac1e37e15783eb9e41c4783ecc48a5597184fa08e793d1043a7e0f892bd85e635739a510c1823ddff273a",
                "address": "addr1qxrtelvca45kah8vszqpnurvcpdkwy9wfmph20eldu53wlmsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvukstdeypu",
            },
        ],
    },
]


#
# Tests
#
class CardanoShelleyTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            shelley_acc_ctx = CardanoShelley.FromCip1852Object(
                Cip1852.FromExtendedKey(test["ex_acc"], test["coin"])
            )

            # Test objects
            self.assertTrue(isinstance(shelley_acc_ctx.StakingObject(), Cip1852))
            self.assertTrue(isinstance(shelley_acc_ctx.PublicKeys(), CardanoShelleyPublicKeys))
            self.assertTrue(isinstance(shelley_acc_ctx.PrivateKeys(), CardanoShelleyPrivateKeys))
            self.assertTrue(shelley_acc_ctx.RewardObject() is shelley_acc_ctx.StakingObject())

            # Test IsPublicOnly
            self.assertFalse(shelley_acc_ctx.IsPublicOnly())

            # Test staking keys and address from StakingObject
            self.assertEqual(test["staking"]["pub_key"], shelley_acc_ctx.StakingObject().PublicKey().RawCompressed().ToHex())
            self.assertEqual(test["staking"]["priv_key"], shelley_acc_ctx.StakingObject().PrivateKey().Raw().ToHex())
            self.assertEqual(test["staking"]["address"], shelley_acc_ctx.StakingObject().PublicKey().ToAddress())

            # Test staking keys and address from PublicKeys/PrivateKeys
            self.assertEqual(test["staking"]["pub_key"], shelley_acc_ctx.PublicKeys().StakingKey().RawCompressed().ToHex())
            self.assertEqual(test["staking"]["priv_key"], shelley_acc_ctx.PrivateKeys().StakingKey().Raw().ToHex())
            self.assertEqual(test["staking"]["address"], shelley_acc_ctx.PublicKeys().ToStakingAddress())
            self.assertEqual(test["staking"]["address"], shelley_acc_ctx.PublicKeys().ToRewardAddress())

            # Test account keys
            self.assertEqual(test["account"]["pub_key"], shelley_acc_ctx.PublicKeys().AddressKey().RawCompressed().ToHex())
            self.assertEqual(test["account"]["priv_key"], shelley_acc_ctx.PrivateKeys().AddressKey().Raw().ToHex())

            # Derive change keys
            shelley_chg_ctx = shelley_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            # Test change keys
            self.assertEqual(test["change"]["pub_key"], shelley_chg_ctx.PublicKeys().AddressKey().RawCompressed().ToHex())
            self.assertEqual(test["change"]["priv_key"], shelley_chg_ctx.PrivateKeys().AddressKey().Raw().ToHex())

            for idx, test_addr in enumerate(test["addresses"]):
                # Derive address keys
                shelley_addr_ctx = shelley_chg_ctx.AddressIndex(idx)

                # Test address keys and address
                self.assertEqual(test_addr["pub_key"], shelley_addr_ctx.PublicKeys().AddressKey().RawCompressed().ToHex())
                self.assertEqual(test_addr["priv_key"], shelley_addr_ctx.PrivateKeys().AddressKey().Raw().ToHex())
                self.assertEqual(test_addr["address"], shelley_addr_ctx.PublicKeys().ToAddress())

    # Test invalid parameters
    def test_invalid_params(self):
        # Construct from a BIP44 object
        bip44 = Bip44.FromSeed(binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f"), Bip44Coins.CARDANO_BYRON_ICARUS)
        self.assertRaises(ValueError, CardanoShelley.FromCip1852Object, bip44)

        # Construct from a not account objecz
        cip1852 = Cip1852.FromSeed(binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f"), Cip1852Coins.CARDANO_ICARUS)
        self.assertRaises(ValueError, CardanoShelley, cip1852, cip1852)
        self.assertRaises(ValueError, CardanoShelley, cip1852.Purpose(), cip1852)
        self.assertRaises(ValueError, CardanoShelley, cip1852.Purpose().Coin(), cip1852)
        self.assertRaises(ValueError, CardanoShelley, cip1852.Purpose().Coin().Account(0), cip1852)
