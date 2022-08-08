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

from bip_utils import (
    Bip32KeyData, Bip32KeyError, Bip44Changes, Bip44Coins, Bip44DepthError, Bip44Levels, Bip44PrivateKey,
    Bip44PublicKey, Bip49Coins, CardanoShelley, Cip1852Coins, Monero
)
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst
from bip_utils.bip.conf.common import BipCoinConf

ZERO_CHAIN_CODE = b"\x00" * Bip32KeyDataConst.CHAINCODE_BYTE_LEN


#
# Helper class for Bip44Base child classes, which share the same tests
#
class Bip44BaseTestHelper:

    # Run all tests in test vector using FromSeed for construction
    @staticmethod
    def test_from_seed(ut_class, bip_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip_mst_ctx = bip_class.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test coin configuration
            ut_class.assertTrue(isinstance(bip_mst_ctx.CoinConf(), BipCoinConf))

            # Test coin names and test net flag
            coin_names = bip_mst_ctx.CoinConf().CoinNames()
            ut_class.assertEqual(test["names"], (coin_names.Name(), coin_names.Abbreviation()))
            ut_class.assertEqual(test["is_testnet"], bip_mst_ctx.CoinConf().IsTestNet())

            # Test key objects
            ut_class.assertTrue(isinstance(bip_mst_ctx.PublicKey(), Bip44PublicKey))
            ut_class.assertTrue(isinstance(bip_mst_ctx.PrivateKey(), Bip44PrivateKey))

            # Test master key
            ut_class.assertEqual(test["ex_master"], bip_mst_ctx.PrivateKey().ToExtended())
            ut_class.assertEqual(test["wif_master"], bip_mst_ctx.PrivateKey().ToWif())

            # Derive account
            bip_acc_ctx = bip_mst_ctx.Purpose().Coin().Account(0)
            # Test account keys
            ut_class.assertEqual(test["account"]["ex_pub"], bip_acc_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["account"]["ex_priv"], bip_acc_ctx.PrivateKey().ToExtended())

            # Derive external chain
            bip_chg_ctx = bip_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            # Test external chain keys
            ut_class.assertEqual(test["chain_ext"]["ex_pub"], bip_chg_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["chain_ext"]["ex_priv"], bip_chg_ctx.PrivateKey().ToExtended())

            # Test addresses
            for idx, test_addr in enumerate(test["addresses"]):
                bip_addr_ctx = bip_chg_ctx.AddressIndex(idx)

                # Use Monero class for Monero coins
                if test["coin"] in (Bip44Coins.MONERO_ED25519_SLIP, Bip44Coins.MONERO_SECP256K1):
                    monero = Monero.FromBip44PrivateKey(bip_addr_ctx.PrivateKey().Bip32Key().KeyObject())
                    addr = monero.PrimaryAddress()
                # Use CardanoShelley class for CIP-1852 coins
                elif isinstance(test["coin"], Cip1852Coins):
                    shelley_ctx = CardanoShelley.FromCip1852Object(
                        bip_acc_ctx).Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx)
                    addr = shelley_ctx.PublicKeys().ToAddress()
                # All other coins
                else:
                    addr = bip_addr_ctx.PublicKey().ToAddress()

                ut_class.assertEqual(test_addr, addr)

            # Only for Cardano: test staking address
            if isinstance(test["coin"], Cip1852Coins):
                shelley_ctx = CardanoShelley.FromCip1852Object(bip_acc_ctx)
                ut_class.assertEqual(test["staking_address"], shelley_ctx.StakingObject().PublicKey().ToAddress())

            # Only for BIP44 Litecoin: test extended keys with alternate versions
            if test["coin"] == Bip44Coins.LITECOIN and "ex_master_alt" in test:
                # Set flag
                test["ex_master_cls"].UseAlternateKeyNetVersions(True)
                # Create from seed
                bip_mst_ltc_ctx = bip_class.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])
                # Test master key
                ut_class.assertEqual(test["ex_master_alt"], bip_mst_ltc_ctx.PrivateKey().ToExtended())
                # Derive account
                bip_lst_acc_ctx = bip_mst_ltc_ctx.Purpose().Coin().Account(0)
                # Test account keys
                ut_class.assertEqual(test["account"]["ex_pub_alt"], bip_lst_acc_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(test["account"]["ex_priv_alt"], bip_lst_acc_ctx.PrivateKey().ToExtended())

                # Derive external chain
                bip_lst_chg_ctx = bip_lst_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
                # Test external chain keys
                ut_class.assertEqual(test["chain_ext"]["ex_pub_alt"], bip_lst_chg_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(test["chain_ext"]["ex_priv_alt"], bip_lst_chg_ctx.PrivateKey().ToExtended())
                # Reset flag
                test["ex_master_cls"].UseAlternateKeyNetVersions(False)

            # Only for Bitcoin Cash and Bitcoin Cash test net: test legacy addresses
            if test["coin"] in (Bip44Coins.BITCOIN_CASH, Bip44Coins.BITCOIN_CASH_TESTNET,
                                Bip44Coins.BITCOIN_CASH_SLP, Bip44Coins.BITCOIN_CASH_SLP_TESTNET,
                                Bip44Coins.ECASH, Bip44Coins.ECASH_TESTNET) and "addresses_legacy" in test:
                # Set flag
                test["addresses_legacy"]["cls"].UseLegacyAddress(True)
                # Test addresses (bip_obj_ctx is already the external chain)
                for idx, test_addr in enumerate(test["addresses_legacy"]["addresses"]):
                    ut_class.assertEqual(test_addr,
                                         bip_chg_ctx.AddressIndex(idx).PublicKey().ToAddress())
                # Reset flag
                test["addresses_legacy"]["cls"].UseLegacyAddress(False)

            # Only for Litecoin and Litecoin test net: test deprecated addresses
            elif test["coin"] in (Bip44Coins.LITECOIN, Bip44Coins.LITECOIN_TESTNET,
                                  Bip49Coins.LITECOIN, Bip49Coins.LITECOIN_TESTNET) and "addresses_depr" in test:
                # Set flag
                test["addresses_depr"]["cls"].UseDeprecatedAddress(True)
                # Test addresses (bip_obj_ctx is already the external chain)
                for idx, test_addr in enumerate(test["addresses_depr"]["addresses"]):
                    ut_class.assertEqual(test_addr, bip_chg_ctx.AddressIndex(idx).PublicKey().ToAddress())
                # Reset flag
                test["addresses_depr"]["cls"].UseDeprecatedAddress(False)

    # Run all tests in test vector using FromExtendedKey for construction
    @staticmethod
    def test_from_ex_key(ut_class, bip_class, test_vector):
        for test in test_vector:
            # Create from private extended master key
            bip_ex_ctx = bip_class.FromExtendedKey(test["ex_master"], test["coin"])
            ut_class.assertEqual(test["ex_master"], bip_ex_ctx.PrivateKey().ToExtended())

            # Test derived keys
            for test_der in (test["account"], test["chain_ext"]):
                # Create from private extended key
                bip_ex_ctx = bip_class.FromExtendedKey(test_der["ex_priv"], test["coin"])
                ut_class.assertFalse(bip_ex_ctx.IsPublicOnly())
                ut_class.assertEqual(test_der["ex_pub"], bip_ex_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(test_der["ex_priv"], bip_ex_ctx.PrivateKey().ToExtended())
                # Create from public extended key
                bip_ex_ctx = bip_class.FromExtendedKey(test_der["ex_pub"], test["coin"])
                ut_class.assertTrue(bip_ex_ctx.IsPublicOnly())
                ut_class.assertEqual(test_der["ex_pub"], bip_ex_ctx.PublicKey().ToExtended())
                ut_class.assertRaises(Bip32KeyError, bip_ex_ctx.PrivateKey)

    # Run all tests in test vector using FromPrivateKey for construction
    @staticmethod
    def test_from_priv_key(ut_class, bip_class, test_vector):
        for test in test_vector:
            for ex_key in (test["ex_master"], test["account"]["ex_priv"], test["chain_ext"]["ex_priv"]):
                bip_ex_ctx = bip_class.FromExtendedKey(ex_key, test["coin"])

                # Create from private key without derivation data
                bip_ctx = bip_class.FromPrivateKey(bip_ex_ctx.PrivateKey().Raw().ToBytes(), test["coin"])
                ut_class.assertFalse(bip_ctx.IsPublicOnly())
                ut_class.assertEqual(bip_ex_ctx.PublicKey().RawCompressed().ToHex(), bip_ctx.PublicKey().RawCompressed().ToHex())
                ut_class.assertEqual(bip_ex_ctx.PrivateKey().Raw().ToHex(), bip_ctx.PrivateKey().Raw().ToHex())
                ut_class.assertEqual(ZERO_CHAIN_CODE, bip_ctx.Bip32Object().ChainCode().ToBytes())
                ut_class.assertEqual(Bip44Levels.MASTER, bip_ctx.Level())
                ut_class.assertEqual(Bip44Levels.MASTER, bip_ctx.Level())
                ut_class.assertTrue(bip_ctx.Bip32Object().ParentFingerPrint().IsMasterKey())

                # Create from private key with derivation data
                bip_ctx = bip_class.FromPrivateKey(
                    bip_ex_ctx.PrivateKey().Raw().ToBytes(),
                    test["coin"],
                    Bip32KeyData(
                        chain_code=bip_ex_ctx.Bip32Object().ChainCode(),
                        depth=bip_ex_ctx.Bip32Object().Depth(),
                        index=bip_ex_ctx.Bip32Object().Index(),
                        parent_fprint=bip_ex_ctx.Bip32Object().ParentFingerPrint()
                    )
                )
                ut_class.assertFalse(bip_ctx.IsPublicOnly())
                ut_class.assertEqual(ex_key, bip_ctx.PrivateKey().ToExtended())

    # Run all tests in test vector using FromPublicKey for construction
    @staticmethod
    def test_from_pub_key(ut_class, bip_class, test_vector):
        for test in test_vector:
            for ex_key in (test["account"]["ex_pub"], test["chain_ext"]["ex_pub"]):
                bip_ex_ctx = bip_class.FromExtendedKey(ex_key, test["coin"])

                # Create from public key without derivation data
                bip_ctx = bip_class.FromPublicKey(bip_ex_ctx.PublicKey().RawCompressed().ToBytes(), test["coin"])
                ut_class.assertTrue(bip_ctx.IsPublicOnly())
                ut_class.assertRaises(Bip32KeyError, bip_ctx.PrivateKey)
                ut_class.assertEqual(bip_ex_ctx.PublicKey().RawCompressed().ToHex(), bip_ctx.PublicKey().RawCompressed().ToHex())
                ut_class.assertEqual(ZERO_CHAIN_CODE, bip_ctx.Bip32Object().ChainCode().ToBytes())
                ut_class.assertEqual(Bip44Levels.ACCOUNT, bip_ctx.Level())
                ut_class.assertEqual(0, bip_ctx.Bip32Object().Index())
                ut_class.assertTrue(bip_ctx.Bip32Object().ParentFingerPrint().IsMasterKey())

                # Create from public key with derivation data
                bip_ctx = bip_class.FromPublicKey(
                    bip_ex_ctx.PublicKey().RawCompressed().ToBytes(),
                    test["coin"],
                    Bip32KeyData(
                        chain_code=bip_ex_ctx.Bip32Object().ChainCode(),
                        depth=bip_ex_ctx.Bip32Object().Depth(),
                        index=bip_ex_ctx.Bip32Object().Index(),
                        parent_fprint=bip_ex_ctx.Bip32Object().ParentFingerPrint()
                    )
                )
                ut_class.assertTrue(bip_ctx.IsPublicOnly())
                ut_class.assertEqual(ex_key, bip_ctx.PublicKey().ToExtended())

    # Test default path derivation
    @staticmethod
    def test_default_path_derivation(ut_class, bip_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip_def_ctx = bip_class.FromSeed(binascii.unhexlify(test["seed"]), test["coin"]).DeriveDefaultPath()
            # Test addresses
            if test["coin"] in (Bip44Coins.MONERO_ED25519_SLIP, Bip44Coins.MONERO_SECP256K1):
                monero = Monero.FromBip44PrivateKey(bip_def_ctx.PrivateKey().Raw().ToBytes())
                def_addr = monero.PrimaryAddress()
            else:
                def_addr = bip_def_ctx.PublicKey().ToAddress()
            ut_class.assertEqual(test["default_address"], def_addr)

    # Test for IsLevel method
    @staticmethod
    def test_is_level(ut_class, bip_class, bip_coin, test_seed_bytes):
        # Master level
        bip_ctx = bip_class.FromSeed(test_seed_bytes, bip_coin)
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.MASTER)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.MASTER))
        # Purpose level
        bip_ctx = bip_ctx.Purpose()
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.PURPOSE)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.PURPOSE))
        # Coin level
        bip_ctx = bip_ctx.Coin()
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.COIN)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.COIN))
        # Account level
        bip_ctx = bip_ctx.Account(0)
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.ACCOUNT)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.ACCOUNT))
        # Change level
        bip_ctx = bip_ctx.Change(Bip44Changes.CHAIN_EXT)
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.CHANGE)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.CHANGE))
        # Address index level
        bip_ctx = bip_ctx.AddressIndex(0)
        ut_class.assertEqual(bip_ctx.Level(), Bip44Levels.ADDRESS_INDEX)
        ut_class.assertTrue(bip_ctx.IsLevel(Bip44Levels.ADDRESS_INDEX))

        # Invalid parameter
        ut_class.assertRaises(TypeError, bip_ctx.IsLevel, 0)

    # Test different key formats
    @staticmethod
    def test_key_formats(ut_class, bip_class, test_data):
        # Create from seed
        bip_ctx = bip_class.FromSeed(binascii.unhexlify(test_data["seed"]), test_data["coin"])
        # Check private key formats
        ut_class.assertEqual(test_data["ex_priv"], bip_ctx.PrivateKey().ToExtended())
        ut_class.assertEqual(test_data["raw_priv"], bip_ctx.PrivateKey().Raw().ToHex())
        # Check public key formats
        ut_class.assertEqual(test_data["ex_pub"], bip_ctx.PublicKey().ToExtended())
        ut_class.assertEqual(test_data["raw_compr_pub"], bip_ctx.PublicKey().RawCompressed().ToHex())
        ut_class.assertEqual(test_data["raw_uncompr_pub"], bip_ctx.PublicKey().RawUncompressed().ToHex())

    # Test construction from extended keys with valid and invalid depths
    @staticmethod
    def test_from_ex_key_depth(ut_class, bip_class, bip_coin, test_data):
        # Private key with depth 5 shall not raise exception
        bip_class.FromExtendedKey(test_data["ex_priv_5"], bip_coin)
        # Private key with depth 6 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_priv_6"], bip_coin)

        # Public key with depth 3 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_pub_2"], bip_coin)
        # Public key with depth 4 or 5 shall not raise exception
        bip_class.FromExtendedKey(test_data["ex_pub_3"], bip_coin)
        bip_class.FromExtendedKey(test_data["ex_pub_5"], bip_coin)
        # Public key with depth 6 shall raise exception
        ut_class.assertRaises(Bip44DepthError, bip_class.FromExtendedKey, test_data["ex_pub_6"], bip_coin)

    # Test type error
    @staticmethod
    def test_type_error(ut_class, bip_class, test_coins):
        # Exception: construct from invalid type
        ut_class.assertRaises(TypeError, bip_class.FromSeed, b"", 0)
        ut_class.assertRaises(TypeError, bip_class.FromExtendedKey, "", 0)
        ut_class.assertRaises(TypeError, bip_class.FromPrivateKey, b"", 0)

        for coin in test_coins:
            ut_class.assertRaises(TypeError, bip_class.FromSeed, b"", coin)
            ut_class.assertRaises(TypeError, bip_class.FromExtendedKey, "", coin)
            ut_class.assertRaises(TypeError, bip_class.FromPrivateKey, b"", coin)

    # Test invalid path derivations
    @staticmethod
    def test_invalid_derivations(ut_class, bip_class, bip_coin, test_seed_bytes):
        # Create all the derivations
        bip_mst_ctx = bip_class.FromSeed(test_seed_bytes, bip_coin)
        bip_prp_ctx = bip_mst_ctx.Purpose()
        bip_coin_ctx = bip_prp_ctx.Coin()
        bip_acc_ctx = bip_coin_ctx.Account(0)
        bip_chg_ctx = bip_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip_addr_ctx = bip_chg_ctx.AddressIndex(0)

        # Invalid change type
        ut_class.assertRaises(TypeError, bip_acc_ctx.Change, 0)
        # Invalid derivation from master
        ut_class.assertRaises(Bip44DepthError, bip_mst_ctx.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_mst_ctx.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_mst_ctx.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_mst_ctx.AddressIndex, 0)
        # Invalid derivation from purpose
        ut_class.assertRaises(Bip44DepthError, bip_prp_ctx.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_prp_ctx.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_prp_ctx.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_prp_ctx.AddressIndex, 0)
        # Invalid derivation from coin
        ut_class.assertRaises(Bip44DepthError, bip_coin_ctx.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_coin_ctx.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_coin_ctx.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_coin_ctx.AddressIndex, 0)
        # Invalid derivation from account
        ut_class.assertRaises(Bip44DepthError, bip_acc_ctx.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_acc_ctx.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_acc_ctx.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_acc_ctx.AddressIndex, 0)
        # Invalid derivation from chain
        ut_class.assertRaises(Bip44DepthError, bip_chg_ctx.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_chg_ctx.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_chg_ctx.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_chg_ctx.Change, Bip44Changes.CHAIN_EXT)
        # Invalid derivation from address index
        ut_class.assertRaises(Bip44DepthError, bip_addr_ctx.Purpose)
        ut_class.assertRaises(Bip44DepthError, bip_addr_ctx.Coin)
        ut_class.assertRaises(Bip44DepthError, bip_addr_ctx.Account, 0)
        ut_class.assertRaises(Bip44DepthError, bip_addr_ctx.Change, Bip44Changes.CHAIN_EXT)
        ut_class.assertRaises(Bip44DepthError, bip_addr_ctx.AddressIndex, 0)
