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
# Base test class for Bip32Base child classes, which share the same tests
#
class Bip32BaseTests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def _test_from_seed_with_child_key(self, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))
            # Test object
            self.__test_bip32_obj(bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(der_path["index"])
                # Test object
                self.__test_bip32_obj(bip32_ctx, der_path, depth, False)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def _test_from_seed_with_derive_path(self, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))
            # Test object
            self.__test_bip32_obj(bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(der_path["path"])
                # Test object
                self.__test_bip32_obj(bip32_from_path, der_path, depth, False)

    # Run all tests in test vector using FromSeedAndPath for construction
    def _test_from_seed_and_path(self, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from seed and path
            bip32_ctx = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), "m")
            # Test object
            self.__test_bip32_obj(bip32_ctx, test["master"], depth, False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Create from seed and path
                bip32_from_path = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), der_path["path"])
                # Test object
                self.__test_bip32_obj(bip32_from_path, der_path, depth, False)

    # Run all tests in test vector using FromExtendedKey for construction
    def _test_from_ex_key(self, bip32_class, test_vector):
        for test in test_vector:
            depth = 0
            # Create from private extended key
            bip32_ctx = bip32_class.FromExtendedKey(test["master"]["ex_priv"])
            # Test object
            self.__test_bip32_obj(bip32_ctx, test["master"], depth, False)

            # Same test for derivation paths
            for der_path in test["der_paths"]:
                depth += 1
                # Create from private extended key
                bip32_ctx = bip32_class.FromExtendedKey(der_path["ex_priv"])
                # Test object
                self.__test_bip32_obj(bip32_ctx, der_path, depth, False)

    # Run all tests in test vector using FromPrivateKey for construction
    def _test_from_priv_key(self, bip32_class, test_vector):
        for test in test_vector:
            priv_key_bytes = binascii.unhexlify(test["master"]["priv_key"])
            priv_key_cls = EllipticCurveGetter.FromType(test["curve_type"]).PrivateKeyClass()

            # Test constructing both from bytes and key object
            self.__test_from_priv_key(bip32_class, test, priv_key_bytes)
            self.__test_from_priv_key(bip32_class, test, priv_key_cls.FromBytes(priv_key_bytes))

    # Test using FromPublicKey for construction
    def _test_from_pub_key(self, bip32_class, test_vector):
        for test in test_vector:
            pub_key_bytes = binascii.unhexlify(test["master"]["pub_key"])
            pub_key_cls = EllipticCurveGetter.FromType(test["curve_type"]).PublicKeyClass()

            # Test constructing both from bytes and key object
            self.__test_from_pub_key(bip32_class, test, pub_key_bytes)
            self.__test_from_pub_key(bip32_class, test, pub_key_cls.FromBytes(pub_key_bytes))

    # Test public derivation from extended key
    def _test_public_derivation_ex_key(self, bip32_class, test_vector):
        # Test by constructing from the private key and converting to public
        bip32_ctx = bip32_class.FromExtendedKey(test_vector["ex_priv"])
        self.assertFalse(bip32_ctx.IsPublicOnly())
        bip32_ctx.ConvertToPublic()
        self.__test_public_derivation_ex_key(bip32_ctx, test_vector)

        # And by constructing directly from the public key
        bip32_ctx = bip32_class.FromExtendedKey(test_vector["ex_pub"])
        self.__test_public_derivation_ex_key(bip32_ctx, test_vector)

    # Test public derivation from public key
    def _test_public_derivation_pub_key(self, bip32_class, test_vector):
        # Test by constructing from the private key and converting to public
        bip32_ctx = bip32_class.FromPrivateKey(binascii.unhexlify(test_vector["priv_key"]))
        self.assertFalse(bip32_ctx.IsPublicOnly())
        bip32_ctx.ConvertToPublic()
        self.__test_public_derivation_pub_key(bip32_ctx, test_vector)

        # And by constructing directly from the public key
        bip32_ctx = bip32_class.FromPublicKey(binascii.unhexlify(test_vector["pub_key"]))
        self.__test_public_derivation_pub_key(bip32_ctx, test_vector)

    # Test elliptic curve
    def _test_elliptic_curve(self, bip32_class, curve_type):
        self.assertEqual(bip32_class.Curve(), EllipticCurveGetter.FromType(curve_type))
        self.assertEqual(bip32_class.CurveType(), curve_type)

    # Test invalid extended key
    def _test_invalid_ex_key(self, bip32_class, test_vector):
        for test in test_vector:
            self.assertRaises(Bip32KeyError, bip32_class.FromExtendedKey, test)

    # Test invalid seed
    def _test_invalid_seed(self, bip32_class, err_seed_bytes):
        self.assertRaises(ValueError, bip32_class.FromSeed, err_seed_bytes)

    # Test from private key
    def __test_from_priv_key(self, bip32_class, test, priv_key):
        # Create from private key without derivation data
        bip32_ctx = bip32_class.FromPrivateKey(priv_key)
        self.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        self.assertEqual(0, bip32_ctx.Depth())
        self.assertEqual(0, bip32_ctx.Index())
        self.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

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
        self.__test_bip32_obj(bip32_ctx, test["master"], depth, False)

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
            self.__test_bip32_obj(bip32_ctx, der_path, depth, False)

    # Test from public key
    def __test_from_pub_key(self, bip32_class, test, pub_key):
        # Create from public key without derivation data
        bip32_ctx = bip32_class.FromPublicKey(pub_key)
        self.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        self.assertEqual(0, bip32_ctx.Depth())
        self.assertEqual(0, bip32_ctx.Index())
        self.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

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
        self.__test_bip32_obj(bip32_ctx, test["master"], depth, True)

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
            self.__test_bip32_obj(bip32_ctx, der_path, depth, True)

    # Test public derivation from extended key
    def __test_public_derivation_ex_key(self, bip32_ctx, test_vector):
        # Shall be public and the public key shall be correct
        self.assertTrue(bip32_ctx.IsPublicOnly())
        self.assertEqual(test_vector["ex_pub"], bip32_ctx.PublicKey().ToExtended())
        # Getting the private key shall raise an exception
        self.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)

        # Test derivation paths
        for test in test_vector["der_paths"]:
            # Public derivation does not support hardened indexes
            if Bip32KeyIndex.IsHardenedIndex(test["index"]):
                self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                self.assertEqual(test["ex_pub"], bip32_ctx.PublicKey().ToExtended())

    # Test public derivation from public key
    def __test_public_derivation_pub_key(self, bip32_ctx, test_vector):
        # Shall be public and the public key shall be correct
        self.assertTrue(bip32_ctx.IsPublicOnly())
        self.assertEqual(test_vector["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
        # Getting the private key shall raise an exception
        self.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)

        # Test derivation paths
        for test in test_vector["der_paths"]:
            # Public derivation does not support hardened indexes
            if Bip32KeyIndex.IsHardenedIndex(test["index"]):
                self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                self.assertEqual(test["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())

    # Test BIP32 object
    def __test_bip32_obj(self, bip32_obj, test, depth, is_watch_only):
        if bip32_obj.IsPublicOnly():
            self.assertRaises(Bip32KeyError, bip32_obj.PrivateKey)
        else:
            self.assertTrue(isinstance(bip32_obj.PrivateKey(), Bip32PrivateKey))
            self.assertEqual(test["ex_priv"], bip32_obj.PrivateKey().ToExtended())
            self.assertEqual(test["priv_key"], bip32_obj.PrivateKey().Raw().ToHex())

        self.assertTrue(isinstance(bip32_obj.PublicKey(), Bip32PublicKey))
        self.assertTrue(isinstance(bip32_obj.ChainCode(), Bip32ChainCode))
        self.assertTrue(isinstance(bip32_obj.Depth(), Bip32Depth))
        self.assertTrue(isinstance(bip32_obj.Index(), Bip32KeyIndex))
        self.assertTrue(isinstance(bip32_obj.KeyNetVersions(), Bip32KeyNetVersions))
        self.assertTrue(isinstance(bip32_obj.FingerPrint(), Bip32FingerPrint))
        self.assertTrue(isinstance(bip32_obj.ParentFingerPrint(), Bip32FingerPrint))

        self.assertEqual(is_watch_only, bip32_obj.IsPublicOnly())
        self.assertEqual(depth, bip32_obj.Depth())
        self.assertEqual(test["index"], bip32_obj.Index())

        self.assertEqual(test["ex_pub"], bip32_obj.PublicKey().ToExtended())
        self.assertEqual(test["pub_key"], bip32_obj.PublicKey().RawCompressed().ToHex())

        self.assertEqual(test["chain_code"], bip32_obj.ChainCode().ToHex())
        self.assertEqual(test["parent_fprint"], bip32_obj.ParentFingerPrint().ToHex())
