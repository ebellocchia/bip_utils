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
from bip_utils import Bip32KeyError, Bip32Utils, EllipticCurveGetter
from bip_utils.bip.bip32.bip32_base import Bip32BaseConst

# Invalid seed for testing
TEST_SEED_ERR = b"000102030405060708090a0b0c0d0e"
# Generic seed for testing
TEST_SEED = b"000102030405060708090a0b0c0d0e0f"
# Zero chain code
ZERO_CHAIN_CODE = b"\x00" * Bip32BaseConst.HMAC_HALF_BYTE_LEN


#
# Helper class for Bip32Base child classes, which share the same tests
#
class Bip32BaseTestHelper:

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    @staticmethod
    def test_from_seed_with_child_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))

            # Test index
            ut_class.assertEqual(test["master"]["index"], bip32_ctx.Index())
            # Test curve type
            ut_class.assertEqual(test["curve_type"], bip32_ctx.PublicKey().CurveType())
            ut_class.assertEqual(test["curve_type"], bip32_ctx.PrivateKey().CurveType())
            # Test key objects
            ut_class.assertTrue(isinstance(bip32_ctx.PublicKey().KeyObject(), EllipticCurveGetter.FromType(test["curve_type"]).PublicKeyClass()))
            ut_class.assertTrue(isinstance(bip32_ctx.PrivateKey().KeyObject(), EllipticCurveGetter.FromType(test["curve_type"]).PrivateKeyClass()))
            # Test extended keys
            ut_class.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())
            # Test public key
            ut_class.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
            ut_class.assertEqual(test["master"]["pub_key"], str(bip32_ctx.PublicKey().RawCompressed()))
            ut_class.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode()), bip32_ctx.PublicKey().RawCompressed().ToBytes())
            ut_class.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode()), bytes(bip32_ctx.PublicKey().RawCompressed()))
            # Test private key
            ut_class.assertEqual(test["master"]["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
            ut_class.assertEqual(test["master"]["priv_key"], str(bip32_ctx.PrivateKey().Raw()))
            ut_class.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode()), bip32_ctx.PrivateKey().Raw().ToBytes())
            ut_class.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode()), bytes(bip32_ctx.PrivateKey().Raw()))
            # Test chain code
            ut_class.assertEqual(test["master"]["chain_code"], binascii.hexlify(bip32_ctx.ChainCode().ToBytes()))
            ut_class.assertEqual(test["master"]["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))

            # Test derivation paths
            for der_path in test["der_paths"]:
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(der_path["index"])
                # Test keys
                ut_class.assertEqual(der_path["index"], bip32_ctx.Index())
                ut_class.assertEqual(der_path["index"], bip32_ctx.PublicKey().Data().Index())
                ut_class.assertEqual(der_path["index"], bip32_ctx.PrivateKey().Data().Index())

                ut_class.assertEqual(der_path["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(der_path["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

                ut_class.assertEqual(der_path["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
                ut_class.assertEqual(der_path["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())

                ut_class.assertEqual(der_path["chain_code"], binascii.hexlify(bip32_ctx.ChainCode().ToBytes()))
                ut_class.assertEqual(der_path["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    @staticmethod
    def test_from_seed_with_derive_path(ut_class, bip32_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip32_ctx = bip32_class.FromSeed(binascii.unhexlify(test["seed"]))
            # Test master key
            ut_class.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for der_path in test["der_paths"]:
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(der_path["path"])
                # Test keys
                ut_class.assertEqual(der_path["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                ut_class.assertEqual(der_path["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromSeedAndPath for construction
    @staticmethod
    def test_from_seed_and_path(ut_class, bip32_class, test_vector):
        for test in test_vector:
            # Create from seed
            bip32_ctx = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), "m")
            # Test master key
            ut_class.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for der_path in test["der_paths"]:
                # Try to build from path and test again
                bip32_from_path = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), der_path["path"])
                # Test keys
                ut_class.assertEqual(der_path["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                ut_class.assertEqual(der_path["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromExtendedKey for construction
    @staticmethod
    def test_from_ex_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            # Create from private extended key
            bip32_ctx = bip32_class.FromExtendedKey(test["master"]["ex_priv"])
            # Test master key
            ut_class.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Same test for derivation paths
            for der_path in test["der_paths"]:
                # Create from private extended key
                bip32_ctx = bip32_class.FromExtendedKey(der_path["ex_priv"])
                # Test keys
                ut_class.assertEqual(der_path["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(der_path["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

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

            print(pub_key_bytes.hex())
            print(pub_key_cls)

            # Test constructing both from bytes and key object
            Bip32BaseTestHelper.__test_from_pub_key(ut_class, bip32_class, test, pub_key_bytes)
            Bip32BaseTestHelper.__test_from_pub_key(ut_class, bip32_class, test, pub_key_cls.FromBytes(priv_key_bytes))

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

    # Test invalid extended key
    @staticmethod
    def test_invalid_ex_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            ut_class.assertRaises(Bip32KeyError, bip32_class.FromExtendedKey, test)

    # Test invalid seed
    @staticmethod
    def test_invalid_seed(ut_class, bip32_class):
        ut_class.assertRaises(ValueError, bip32_class.FromSeed, binascii.unhexlify(TEST_SEED_ERR))

    # Test from private key
    @staticmethod
    def __test_from_priv_key(ut_class, bip32_class, test, priv_key):
        # Create from private key
        bip32_ctx = bip32_class.FromPrivateKey(priv_key)
        # Test master key
        ut_class.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
        ut_class.assertEqual(test["master"]["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
        ut_class.assertEqual(0, bip32_ctx.Depth())
        ut_class.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

        # Same test for derivation paths
        for der_path in test["der_paths"]:
            # Create from private key
            bip32_ctx = bip32_class.FromPrivateKey(binascii.unhexlify(der_path["priv_key"]))
            # Test keys
            ut_class.assertEqual(der_path["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
            ut_class.assertEqual(der_path["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
            ut_class.assertEqual(0, bip32_ctx.Depth())
            ut_class.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
            ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

    # Test from public key
    @staticmethod
    def __test_from_pub_key(ut_class, bip32_class, test, pub_key):
        # Create from public key
        bip32_ctx = bip32_class.FromPublicKey(pub_key)
        # Test master key
        ut_class.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
        ut_class.assertEqual(0, bip32_ctx.Depth())
        ut_class.assertEqual(ZERO_CHAIN_CODE, bip32_ctx.ChainCode().ToBytes())
        ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

        ut_class.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)

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
            if Bip32Utils.IsHardenedIndex(test["index"]):
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
            if Bip32Utils.IsHardenedIndex(test["index"]):
                ut_class.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                ut_class.assertEqual(test["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
