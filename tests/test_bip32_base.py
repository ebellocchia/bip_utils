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
from bip_utils import Bip32KeyError, Bip32Utils
from bip_utils.bip32.bip32_base import Bip32BaseConst

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
            # Test master key
            ut_class.assertEqual(test["master"]["index"], int(bip32_ctx.Index()))

            ut_class.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            ut_class.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            ut_class.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
            ut_class.assertEqual(test["master"]["pub_key"], str(bip32_ctx.PublicKey().RawCompressed()))
            ut_class.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode("utf-8")), bip32_ctx.PublicKey().RawCompressed().ToBytes())
            ut_class.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode("utf-8")), bytes(bip32_ctx.PublicKey().RawCompressed()))

            ut_class.assertEqual(test["master"]["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
            ut_class.assertEqual(test["master"]["priv_key"], str(bip32_ctx.PrivateKey().Raw()))
            ut_class.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode("utf-8")), bip32_ctx.PrivateKey().Raw().ToBytes())
            ut_class.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode("utf-8")), bytes(bip32_ctx.PrivateKey().Raw()))

            ut_class.assertEqual(test["master"]["chain_code"], binascii.hexlify(bip32_ctx.ChainCode()))
            ut_class.assertEqual(test["master"]["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))
            ut_class.assertEqual(test["master"]["parent_fprint"], binascii.hexlify(bytes(bip32_ctx.ParentFingerPrint())))

            # Test derivation paths
            for chain in test["der_paths"]:
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(chain["index"])
                # Test keys
                ut_class.assertEqual(chain["index"], int(bip32_ctx.Index()))

                ut_class.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

                ut_class.assertEqual(chain["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
                ut_class.assertEqual(chain["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())

                ut_class.assertEqual(chain["chain_code"], binascii.hexlify(bip32_ctx.ChainCode()))
                ut_class.assertEqual(chain["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))
                ut_class.assertEqual(chain["parent_fprint"], binascii.hexlify(bytes(bip32_ctx.ParentFingerPrint())))

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
            for chain in test["der_paths"]:
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(chain["path"][2:])
                # Test keys
                ut_class.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                ut_class.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

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
            for chain in test["der_paths"]:
                # Try to build from path and test again
                bip32_from_path = bip32_class.FromSeedAndPath(binascii.unhexlify(test["seed"]), chain["path"])
                # Test keys
                ut_class.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                ut_class.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

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
            for chain in test["der_paths"]:
                # Create from private extended key
                bip32_ctx = bip32_class.FromExtendedKey(chain["ex_priv"])
                # Test keys
                ut_class.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                ut_class.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

    # Run all tests in test vector using FromPrivateKey for construction
    @staticmethod
    def test_from_priv_key(ut_class, bip32_class, test_vector):
        zero_chain_code = b"\x00" * Bip32BaseConst.HMAC_HALF_LEN

        for test in test_vector:
            # Create from private key
            bip32_ctx = bip32_class.FromPrivateKey(binascii.unhexlify(test["master"]["priv_key"]))
            # Test master key
            ut_class.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
            ut_class.assertEqual(test["master"]["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
            ut_class.assertEqual(0, bip32_ctx.Depth())
            ut_class.assertEqual(zero_chain_code, bip32_ctx.ChainCode())
            ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

            # Same test for derivation paths
            for chain in test["der_paths"]:
                # Create from private key
                bip32_ctx = bip32_class.FromPrivateKey(binascii.unhexlify(chain["priv_key"]))
                # Test keys
                ut_class.assertEqual(chain["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
                ut_class.assertEqual(chain["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
                ut_class.assertEqual(0, bip32_ctx.Depth())
                ut_class.assertEqual(zero_chain_code, bip32_ctx.ChainCode())
                ut_class.assertTrue(bip32_ctx.ParentFingerPrint().IsMasterKey())

    # Test public derivation
    @staticmethod
    def test_public_derivation(ut_class, bip32_class, test_vector):
        # Construct from extended private key
        bip32_ctx = bip32_class.FromExtendedKey(test_vector["ex_priv"])
        # Shall not be public
        ut_class.assertFalse(bip32_ctx.IsPublicOnly())

        # Convert to public
        bip32_ctx.ConvertToPublic()
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

    # Test invalid seed
    @staticmethod
    def test_invalid_seed(ut_class, bip32_class, test_vector):
        for test in test_vector:
            ut_class.assertRaises(ValueError, bip32_class.FromSeed, binascii.unhexlify(test))

    # Test invalid extended key
    @staticmethod
    def test_invalid_ex_key(ut_class, bip32_class, test_vector):
        for test in test_vector:
            ut_class.assertRaises(Bip32KeyError, bip32_class.FromExtendedKey, test)
