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
    Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyData, Bip32KeyError, Bip32KeyIndex, Bip32KeyNetVersions,
    Bip32PrivateKey, Bip32PublicKey, EllipticCurveGetter
)
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst


# Generic seed for testing
TEST_SEED = b"\x00" * Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN
# Zero chain code
ZERO_CHAIN_CODE = b"\x00" * Bip32KeyDataConst.CHAINCODE_BYTE_LEN


#
# Helper class for Bip32Base child classes, which share the same tests
#
class Bip32BaseTestHelper:

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    @staticmethod
    def test_from_seed_with_child_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(der_path["index"])
                # Test object
                Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, der_path, depth, False)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    @staticmethod
    def test_from_seed_with_derive_path(ut_class, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(der_path["path"])
                # Test object
                Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_from_path, der_path, depth, False)

    # Run all tests in test vector using FromSeedAndPath for construction
    @staticmethod
    def test_from_seed_and_path(ut_class, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed and path
            bip32_ctx = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), "m")
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Create from seed and path
                bip32_from_path = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), der_path["path"])
                # Test object
                Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_from_path, der_path, depth, False)

    # Run all tests in test vector using FromExtendedKey for construction
    @staticmethod
    def test_from_ex_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from private extended key
            bip32_ctx = bip32_class.FromExtendedKey(test["master"]["ex_priv"])
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, False)

            # Same test for derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Create from private extended key
                bip32_ctx = bip32_class.FromExtendedKey(der_path["ex_priv"])
                # Test object
                Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, der_path, depth, False)

    # Run all tests in test vector using FromPrivateKey for construction
    @staticmethod
    def test_from_priv_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            priv_key_bytes = binascii.unhexlify(test["master"]["priv_key"])
            priv_key_cls = EllipticCurveGetter.FromType(test["curve_type"]).PrivateKeyClass()

            # Test constructing both from bytes and key object
            Bip32BaseTestHelper.__test_from_priv_key(ut_class, bip32_class, test, priv_key_bytes)
            Bip32BaseTestHelper.__test_from_priv_key(ut_class, bip32_class, test, priv_key_cls.FromBytes(priv_key_bytes))

    # Test using FromPublicKey for construction
    @staticmethod
    def test_from_pub_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            pub_key_bytes = binascii.unhexlify(test["master"]["pub_key"])
            pub_key_cls = EllipticCurveGetter.FromType(test["curve_type"]).PublicKeyClass()

            # Test constructing both from bytes and key object
            Bip32BaseTestHelper.__test_from_pub_key(ut_class, bip32_class, test, pub_key_bytes)
            Bip32BaseTestHelper.__test_from_pub_key(ut_class, bip32_class, test, pub_key_cls.FromBytes(pub_key_bytes))

    # Test public derivation from extended key
    @staticmethod
    def test_public_derivation_ex_key(ut_class, bip32_class, test_vector):
        # Test by constructing from the private key and converting to public
        bip32_ctx = bip32_class.FromExtendedKey(test_vector["ex_priv"])
        ut_class.assertFalse(bip32_ctx.IsPublicOnly())
        bip32_ctx.ConvertToPublic()
        Bip32BaseTestHelper.__test_public_derivation_ex_key(ut_class, bip32_ctx, test_vector)

        # And by constructing directly from the public key
        bip32_ctx = bip32_class.FromExtendedKey(test_vector["ex_pub"])
        Bip32BaseTestHelper.__test_public_derivation_ex_key(ut_class, bip32_ctx, test_vector)

    # Test public derivation from public key
    @staticmethod
    def test_public_derivation_pub_key(ut_class, bip32_class, test_vector):
        # Test by constructing from the private key and converting to public
        bip32_ctx = bip32_class.FromPrivateKey(binascii.unhexlify(test_vector["priv_key"]))
        ut_class.assertFalse(bip32_ctx.IsPublicOnly())
        bip32_ctx.ConvertToPublic()
        Bip32BaseTestHelper.__test_public_derivation_pub_key(ut_class, bip32_ctx, test_vector)

        # And by constructing directly from the public key
        bip32_ctx = bip32_class.FromPublicKey(binascii.unhexlify(test_vector["pub_key"]))
        Bip32BaseTestHelper.__test_public_derivation_pub_key(ut_class, bip32_ctx, test_vector)

    # Test elliptic curve
    @staticmethod
    def test_elliptic_curve(ut_class, bip32_class, curve_type):
        ut_class.assertEqual(bip32_class.Curve(), EllipticCurveGetter.FromType(curve_type))
        ut_class.assertEqual(bip32_class.CurveType(), curve_type)

    # Test invalid extended key
    @staticmethod
    def test_invalid_ex_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            ut_class.assertRaises(Bip32KeyError, bip32_class.FromExtendedKey, test)

    # Test invalid seed
    @staticmethod
    def test_invalid_seed(ut_class, bip32_class, err_seed_bytes):
        ut_class.assertRaises(ValueError, bip32_class.FromSeed, err_seed_bytes)

    # Test from private key
    @staticmethod
    def __test_from_priv_key(ut_class, bip32_class, test, priv_key):
        # Create from private key without derivation data
        bip32_ctx = bip32_class.FromPrivateKey(priv_key)
        ut_class.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        ut_class.assertEqual(0, bip32_ctx.Depth())
        ut_class.assertEqual(0, bip32_ctx.Index())
        ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

        # Create from private key with derivation data
        depth = 0
        bip32_ctx = bip32_class.FromPrivateKey(
            priv_key,
            Bip32KeyData(
                chain_code=binascii.unhexlify(test["master"]["chain_code"]),
                depth=depth,
                index=test["master"]["index"],
                parent_fprint=binascii.unhexlify(test["master"]["parent_fprint"])
            )
        )
        # Test object
        Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, False)

        # Same test for derivation paths
        for der_path in test["der_paths"]:
            depth += 1
            # Create from private key
            bip32_ctx = bip32_class.FromPrivateKey(
                binascii.unhexlify(der_path["priv_key"]),
                Bip32KeyData(
                    chain_code=binascii.unhexlify(der_path["chain_code"]),
                    depth=depth,
                    index=der_path["index"],
                    parent_fprint=binascii.unhexlify(der_path["parent_fprint"])
                )
            )
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, der_path, depth, False)

    # Test from public key
    @staticmethod
    def __test_from_pub_key(ut_class, bip32_class, test, pub_key):
        # Create from public key without derivation data
        bip32_ctx = bip32_class.FromPublicKey(pub_key)
        ut_class.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        ut_class.assertEqual(0, bip32_ctx.Depth())
        ut_class.assertEqual(0, bip32_ctx.Index())
        ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

        # Create from public key with derivation data
        depth = 0
        bip32_ctx = bip32_class.FromPublicKey(
            pub_key,
            Bip32KeyData(
                chain_code=binascii.unhexlify(test["master"]["chain_code"]),
                depth=depth,
                index=test["master"]["index"],
                parent_fprint=binascii.unhexlify(test["master"]["parent_fprint"])
            )
        )
        # Test object
        Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, test["master"], depth, True)

        # Same test for derivation paths
        for der_path in test["der_paths"]:
            depth += 1
            # Create from public key
            bip32_ctx = bip32_class.FromPublicKey(
                binascii.unhexlify(der_path["pub_key"]),
                Bip32KeyData(
                    chain_code=binascii.unhexlify(der_path["chain_code"]),
                    depth=depth,
                    index=der_path["index"],
                    parent_fprint=binascii.unhexlify(der_path["parent_fprint"])
                )
            )
            # Test object
            Bip32BaseTestHelper.__test_bip32_obj(ut_class, bip32_ctx, der_path, depth, True)

    # Test public derivation from extended key
    @staticmethod
    def __test_public_derivation_ex_key(ut_class, bip32_ctx, test_vector):
        # Shall be public and the public key shall be correct
        ut_class.assertTrue(bip32_ctx.IsPublicOnly())
        ut_class.assertEqual(test_vector["ex_pub"], bip32_ctx.PublicKey().ToExtended())
        # Getting the private key shall raise an exception
        ut_class.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)

        # Test derivation paths
        for test in test_vector["der_paths"]:
            # Public derivation does not support hardened indexes
            if Bip32KeyIndex.IsHardenedIndex(test["index"]):
                ut_class.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                ut_class.assertEqual(test["ex_pub"], bip32_ctx.PublicKey().ToExtended())

    # Test public derivation from public key
    @staticmethod
    def __test_public_derivation_pub_key(ut_class, bip32_ctx, test_vector):
        # Shall be public and the public key shall be correct
        ut_class.assertTrue(bip32_ctx.IsPublicOnly())
        ut_class.assertEqual(test_vector["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
        # Getting the private key shall raise an exception
        ut_class.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)

        # Test derivation paths
        for test in test_vector["der_paths"]:
            # Public derivation does not support hardened indexes
            if Bip32KeyIndex.IsHardenedIndex(test["index"]):
                ut_class.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                ut_class.assertEqual(test["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())

    # Test BIP32 object
    @staticmethod
    def __test_bip32_obj(ut_class, bip32_obj, test, depth, is_watch_only):
        if bip32_obj.IsPublicOnly():
            ut_class.assertRaises(Bip32KeyError, bip32_obj.PrivateKey)
        else:
            ut_class.assertTrue(isinstance(bip32_obj.PrivateKey(), Bip32PrivateKey))
            ut_class.assertEqual(test["ex_priv"], bip32_obj.PrivateKey().ToExtended())
            ut_class.assertEqual(test["priv_key"], bip32_obj.PrivateKey().Raw().ToHex())

        ut_class.assertTrue(isinstance(bip32_obj.PublicKey(), Bip32PublicKey))
        ut_class.assertTrue(isinstance(bip32_obj.ChainCode(), Bip32ChainCode))
        ut_class.assertTrue(isinstance(bip32_obj.Depth(), Bip32Depth))
        ut_class.assertTrue(isinstance(bip32_obj.Index(), Bip32KeyIndex))
        ut_class.assertTrue(isinstance(bip32_obj.KeyNetVersions(), Bip32KeyNetVersions))
        ut_class.assertTrue(isinstance(bip32_obj.FingerPrint(), Bip32FingerPrint))
        ut_class.assertTrue(isinstance(bip32_obj.ParentFingerPrint(), Bip32FingerPrint))

        ut_class.assertEqual(is_watch_only, bip32_obj.IsPublicOnly())
        ut_class.assertEqual(depth, bip32_obj.Depth())
        ut_class.assertEqual(test["index"], bip32_obj.Index())

        ut_class.assertEqual(test["ex_pub"], bip32_obj.PublicKey().ToExtended())
        ut_class.assertEqual(test["pub_key"], bip32_obj.PublicKey().RawCompressed().ToHex())

        ut_class.assertEqual(test["chain_code"], bip32_obj.ChainCode().ToHex())
        ut_class.assertEqual(test["parent_fprint"], bip32_obj.ParentFingerPrint().ToHex())
