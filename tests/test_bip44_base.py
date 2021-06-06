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
from bip_utils import (
    Bip44Coins, Bip44Changes, Bip44Levels,
    Bip44DepthError, Bip44CoinNotAllowedError,
    Bip32KeyError,
    BitcoinCashConf,
    LitecoinConf,
)

#
# Helper class for Bip44Base child classes, which share the same tests
#
class Bip44BaseTestHelper:

    # Run all tests in test vector using FromSeed for construction
    @staticmethod
    def test_from_seed(ut_class, bip_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip_obj_ctx = bip_class.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test coin names and test net flag
            coin_names = bip_obj_ctx.CoinConf().CoinNames()
            ut_class.assertEqual(test["names"], (coin_names.Name(), coin_names.Abbreviation()))
            ut_class.assertEqual(test["is_testnet"], bip_obj_ctx.CoinConf().IsTestNet())

            # Test master key
            ut_class.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey().ToExtended())
            ut_class.assertEqual(test["wif_master"], bip_obj_ctx.PrivateKey().ToWif(False))

            # Derive account
            bip_obj_ctx = bip_obj_ctx.Purpose().Coin().Account(0)
            # Test account keys
            ut_class.assertEqual(test["account"]["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Derive external chain
            bip_obj_ctx = bip_obj_ctx.Change(Bip44Changes.CHAIN_EXT)
            # Test external chain keys
            ut_class.assertEqual(test["chain_ext"]["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Test external chain addresses
            for i in range(len(test["addresses"])):
                bip_obj_addr_ctx = bip_obj_ctx.AddressIndex(i)
                ut_class.assertEqual(test["addresses"][i], bip_obj_addr_ctx.PublicKey().ToAddress())

            # Only for Litecoin: test extended keys with alternate versions
            if test["coin"] == Bip44Coins.LITECOIN and "ex_master_alt" in test:
                # Set flag
                LitecoinConf.EX_KEY_ALT = True
                # Create from seed
                bip_obj_ctx = bip_class.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])
                # Test master key
                ut_class.assertEqual(test["ex_master_alt"], bip_obj_ctx.PrivateKey().ToExtended())
                # Derive account
                bip_obj_ctx = bip_obj_ctx.Purpose().Coin().Account(0)
                # Test account keys
                ut_class.assertEqual(test["account"]["ex_pub_alt"], bip_obj_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(test["account"]["ex_priv_alt"], bip_obj_ctx.PrivateKey().ToExtended())

                # Derive external chain
                bip_obj_ctx = bip_obj_ctx.Change(Bip44Changes.CHAIN_EXT)
                # Test external chain keys
                ut_class.assertEqual(test["chain_ext"]["ex_pub_alt"], bip_obj_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(test["chain_ext"]["ex_priv_alt"], bip_obj_ctx.PrivateKey().ToExtended())
                # Reset flag
                LitecoinConf.EX_KEY_ALT = False

            # Only for Bitcoin Cash and Bitcoin Cash test net, test legacy addresses
            if test["coin"] in (
            Bip44Coins.BITCOIN_CASH, Bip44Coins.BITCOIN_CASH_TESTNET) and "addresses_legacy" in test:
                # Set flag
                BitcoinCashConf.LEGACY_ADDR = True
                # Test addresses (bip_obj_ctx is already the external chain)
                for i in range(len(test["addresses_legacy"])):
                    ut_class.assertEqual(test["addresses_legacy"][i],
                                         bip_obj_ctx.AddressIndex(i).PublicKey().ToAddress())
                # Reset flag
                BitcoinCashConf.LEGACY_ADDR = False

            # Only for Litecoin and Litecoin test net, test deprecated addresses
            if test["coin"] in (Bip44Coins.LITECOIN, Bip44Coins.LITECOIN_TESTNET) and "addresses_depr" in test:
                # Set flag
                LitecoinConf.P2SH_DEPR_ADDR = True
                # Test addresses (bip_obj_ctx is already the external chain)
                for i in range(len(test["addresses_depr"])):
                    ut_class.assertEqual(test["addresses_depr"][i], bip_obj_ctx.AddressIndex(i).PublicKey().ToAddress())
                # Reset flag
                LitecoinConf.P2SH_DEPR_ADDR = False

    # Run all tests in test vector using FromExtendedKey for construction
    @staticmethod
    def test_from_ex_key(ut_class, bip_class, test_vector):
        for test in test_vector:
            # Create from private master key
            bip_obj_ctx = bip_class.FromExtendedKey(test["ex_master"], test["coin"])

            # Test master key
            ut_class.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from private account key
            bip_obj_ctx = bip_class.FromExtendedKey(test["account"]["ex_priv"], test["coin"])
            # Test account keys
            ut_class.assertEqual(test["account"]["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from private change key
            bip_obj_ctx = bip_class.FromExtendedKey(test["chain_ext"]["ex_priv"], test["coin"])
            # Test external chain keys
            ut_class.assertFalse(bip_obj_ctx.IsPublicOnly())
            ut_class.assertEqual(test["chain_ext"]["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from public change key
            bip_obj_ctx = bip_class.FromExtendedKey(test["chain_ext"]["ex_pub"], test["coin"])
            ut_class.assertTrue(bip_obj_ctx.IsPublicOnly())
            ut_class.assertEqual(test["chain_ext"]["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
            ut_class.assertRaises(Bip32KeyError, bip_obj_ctx.PrivateKey)

    # Test for IsLevel method
    @staticmethod
    def test_is_level(ut_class, bip_class, test_seed_bytes):
        # Master level
        bip_obj_ctx = bip_class.FromSeed(binascii.unhexlify(test_seed_bytes), Bip44Coins.BITCOIN)
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.MASTER))
        # Purpose level
        bip_obj_ctx = bip_obj_ctx.Purpose()
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.PURPOSE))
        # Coin level
        bip_obj_ctx = bip_obj_ctx.Coin()
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.COIN))
        # Account level
        bip_obj_ctx = bip_obj_ctx.Account(0)
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.ACCOUNT))
        # Change level
        bip_obj_ctx = bip_obj_ctx.Change(Bip44Changes.CHAIN_EXT)
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.CHANGE))
        # Address index level
        bip_obj_ctx = bip_obj_ctx.AddressIndex(0)
        ut_class.assertTrue(bip_obj_ctx.IsLevel(Bip44Levels.ADDRESS_INDEX))

        # Invalid parameter
        ut_class.assertRaises(TypeError, bip_obj_ctx.IsLevel, 0)

    # Test different key formats
    @staticmethod
    def test_key_formats(ut_class, bip_class, test_data):
        # Create from seed
        bip_obj_ctx = bip_class.FromSeed(binascii.unhexlify(test_data["seed"]), test_data["coin"])
        # Check private key formats
        ut_class.assertEqual(test_data["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())
        ut_class.assertEqual(test_data["raw_priv"], bip_obj_ctx.PrivateKey().Raw().ToHex())
        # Check public key formats
        ut_class.assertEqual(test_data["ex_pub"], bip_obj_ctx.PublicKey().ToExtended())
        ut_class.assertEqual(test_data["raw_compr_pub"], bip_obj_ctx.PublicKey().RawCompressed().ToHex())
        ut_class.assertEqual(test_data["raw_uncompr_pub"], bip_obj_ctx.PublicKey().RawUncompressed().ToHex())

    # Test construction from extended keys with valid and invalid depths
    @staticmethod
    def test_from_ex_key_depth(ut_class, bip_class, test_data):
        # Private key with depth 5 shall not raise exception
        bip_class.FromExtendedKey(test_data["ex_priv_5"], Bip44Coins.BITCOIN)
        # Private key with depth 6 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_priv_6"], Bip44Coins.BITCOIN)

        # Public key with depth 3 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_pub_2"], Bip44Coins.BITCOIN)
        # Public key with depth 4 or 5 shall not raise exception
        bip_class.FromExtendedKey(test_data["ex_pub_3"], Bip44Coins.BITCOIN)
        bip_class.FromExtendedKey(test_data["ex_pub_5"], Bip44Coins.BITCOIN)
        # Public key with depth 6 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_pub_6"], Bip44Coins.BITCOIN)

    # Test coins
    @staticmethod
    def test_coins(ut_class, bip_class, test_coins):
        # Test not allowed coins
        for test in test_coins["not_allowed"]:
            ut_class.assertFalse(bip_class.IsCoinAllowed(test))
            ut_class.assertRaises(Bip44CoinNotAllowedError, bip_class.FromSeed, binascii.unhexlify(test_coins["seed"]),
                                  test)
            ut_class.assertRaises(Bip44CoinNotAllowedError, bip_class.FromExtendedKey, test_coins["ex_key"], test)

        # Test allowed coins
        for test in test_coins["allowed"]:
            ut_class.assertTrue(bip_class.IsCoinAllowed(test))

        # Exception: construct from invalid type
        ut_class.assertRaises(TypeError, bip_class.FromSeed, binascii.unhexlify(test_coins["seed"]), 0)
        ut_class.assertRaises(TypeError, bip_class.FromExtendedKey, test_coins["ex_key"], 0)
        # Exception: invalid type
        ut_class.assertRaises(TypeError, bip_class.IsCoinAllowed, 0)

    # Test invalid path derivations
    @staticmethod
    def test_invalid_derivations(ut_class, bip_class, test_seed_bytes):
        # Create all the derivations
        bip_obj_mst = bip_class.FromSeed(binascii.unhexlify(test_seed_bytes), Bip44Coins.BITCOIN)
        bip_obj_prp = bip_obj_mst.Purpose()
        bip_obj_coin = bip_obj_prp.Coin()
        bip_obj_acc = bip_obj_coin.Account(0)
        bip_obj_change = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip_obj_addr = bip_obj_change.AddressIndex(0)

        # Invalid change type
        ut_class.assertRaises(TypeError, bip_obj_acc.Change, 0)
        # Invalid derivation from master
        ut_class.assertRaises(Bip44DepthError, bip_obj_mst.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_obj_mst.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_obj_mst.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_obj_mst.AddressIndex, 0)
        # Invalid derivation from purpose
        ut_class.assertRaises(Bip44DepthError, bip_obj_prp.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_obj_prp.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_obj_prp.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_obj_prp.AddressIndex, 0)
        # Invalid derivation from coin
        ut_class.assertRaises(Bip44DepthError, bip_obj_coin.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_obj_coin.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_obj_coin.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_obj_coin.AddressIndex, 0)
        # Invalid derivation from account
        ut_class.assertRaises(Bip44DepthError, bip_obj_acc.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_obj_acc.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_obj_acc.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_obj_acc.AddressIndex, 0)
        # Invalid derivation from chain
        ut_class.assertRaises(Bip44DepthError, bip_obj_change.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_obj_change.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_obj_change.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_obj_change.Change, Bip44Changes.CHAIN_EXT)
        # Invalid derivation from address index
        ut_class.assertRaises(Bip44DepthError, bip_obj_addr.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_obj_addr.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_obj_addr.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_obj_addr.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_obj_addr.AddressIndex, 0)
