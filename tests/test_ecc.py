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
import ecdsa
import ed25519_blake2b
import unittest
from ecdsa.ecdsa import generator_256, generator_secp256k1
from ecdsa import ellipticcurve
from nacl import signing
from bip_utils import (
    EllipticCurveGetter, EllipticCurveTypes,
    Ed25519, Ed25519Point, Ed25519PublicKey, Ed25519PrivateKey,
    Ed25519Blake2b, Ed25519Blake2bPublicKey, Ed25519Blake2bPrivateKey,
    Nist256p1, Nist256p1Point, Nist256p1PublicKey, Nist256p1PrivateKey,
    Secp256k1, Secp256k1Point, Secp256k1PublicKey, Secp256k1PrivateKey
)

# Tests for ed25519 invalid public keys
TEST_VECT_ED25519_PUB_KEY_INVALID = [
    # Public key with valid length but wrong version
    b"01e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547",
    # Public key with invalid length
    b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a6149954711",
]

# Tests for ECDSA invalid public keys
TEST_VECT_ECDSA_PUB_KEY_INVALID = [
    # Private key
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
    # Compressed public key with valid length but wrong version
    b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
    # Compressed public key with invalid length
    b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
    # Uncompressed public key with valid length but wrong version
    b"058ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
    # Uncompressed public key with invalid length
    b"04fd87569e9af6015d9d938c67c68fcdf5440d3c235eccbc1195a1924bba90e5e1954cb6d841054791ac227a8c11f79f77d24a20b238402c5424c8e436bb49",
]

# Tests for nist256p1 invalid public keys
TEST_VECT_NIST256P1_PUB_KEY_INVALID = TEST_VECT_ECDSA_PUB_KEY_INVALID
# Tests for secp256k1 invalid public keys
TEST_VECT_SECP256K1_PUB_KEY_INVALID = TEST_VECT_ECDSA_PUB_KEY_INVALID

# Tests for ed25519 invalid private keys
TEST_VECT_ED25519_PRIV_KEY_INVALID = [
    # Private keys with invalid length
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e",
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e71d0",
]

# Tests for nist256p1 invalid private keys
TEST_VECT_NIST256P1_PRIV_KEY_INVALID = TEST_VECT_ED25519_PRIV_KEY_INVALID
# Tests for secp256k1 invalid private keys
TEST_VECT_SECP256K1_PRIV_KEY_INVALID = TEST_VECT_ED25519_PRIV_KEY_INVALID

# Some valid ed25519 keys
TEST_ED25519_COMPR_PUB_KEY = b"007d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c"
TEST_ED25519_UNCOMPR_PUB_KEY = b"007d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c"
TEST_ED25519_PRIV_KEY = b"63326e09d412622906496bdde342b4a60410b3f48db5e74a27bfc1b0b044f80b"

# Some valid secp256k1 keys
TEST_SECP256K1_COMPR_PUB_KEY = b"02c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4"
TEST_SECP256K1_UNCOMPR_PUB_KEY = b"04c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4ec9654b17e30a8a5232078201ecf5cc702dfbb70266aecf16b1f81d85e6b9942"
TEST_SECP256K1_PRIV_KEY = b"e1d36931d581b4dcae0bb03929adcfb5ab0cdc0f4886ff6c5098591636ace214"

# Some valid nist256p1 keys
TEST_NIST256P1_COMPR_PUB_KEY = b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b"
TEST_NIST256P1_UNCOMPR_PUB_KEY = b"048ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b465656d4dd23293a66bbbd3cc07cf6e5b1cd3b81d8e3da4eed050ac0ab2094b9"
TEST_NIST256P1_PRIV_KEY = b"e44c51393e98a691439f74c2060138fa2bcefae59ab277bd81907c93fb16fce1"

#
# Tests
#
class EccTests(unittest.TestCase):
    # Test elliptic curve getter
    def test_elliptic_curve_getter(self):
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.ED25519) is Ed25519)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.NIST256P1) is Nist256p1)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.SECP256K1) is Secp256k1)
        self.assertRaises(TypeError, EllipticCurveGetter.FromType, 0)

    # Test Ed25519 class
    def test_ed25519(self):
        self.assertEqual(Ed25519.Name(), "Ed25519")
        self.assertEqual(Ed25519.Order(), 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED)
        self.assertEqual(Ed25519.Generator().X(), 15112221349535400772501151409588531511454012693041857206046113283949847762202)
        self.assertEqual(Ed25519.Generator().Y(), 46316835694926478169428394003475163141307993866256225615783033603165251855960)
        self.assertEqual(Ed25519.Generator().Order(), 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED)
        self.assertTrue(Ed25519.PointClass() is Ed25519Point)
        self.assertTrue(Ed25519.PublicKeyClass() is Ed25519PublicKey)
        self.assertTrue(Ed25519.PrivateKeyClass() is Ed25519PrivateKey)

        self.assertEqual(Ed25519PublicKey.CurveType(), EllipticCurveTypes.ED25519)
        self.assertEqual(Ed25519PrivateKey.CurveType(), EllipticCurveTypes.ED25519)

        self.assertEqual(Ed25519PublicKey.CompressedLength(), 33)
        self.assertEqual(Ed25519PublicKey.UncompressedLength(), 33)
        self.assertEqual(Ed25519PrivateKey.Length(), 32)

        self.assertTrue(isinstance(Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)).UnderlyingObject(), signing.VerifyKey))
        self.assertTrue(isinstance(Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_UNCOMPR_PUB_KEY)).UnderlyingObject(), signing.VerifyKey))
        self.assertTrue(isinstance(Ed25519PrivateKey(binascii.unhexlify(TEST_ED25519_PRIV_KEY)).UnderlyingObject(), signing.SigningKey))

    # Test Ed25519-Blake2b class
    def test_ed25519_blake2b(self):
        self.assertEqual(Ed25519Blake2b.Name(), "Ed25519-Blake2b")
        self.assertEqual(Ed25519Blake2b.Order(), 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED)
        self.assertEqual(Ed25519Blake2b.Generator().X(), 15112221349535400772501151409588531511454012693041857206046113283949847762202)
        self.assertEqual(Ed25519Blake2b.Generator().Y(), 46316835694926478169428394003475163141307993866256225615783033603165251855960)
        self.assertEqual(Ed25519Blake2b.Generator().Order(), 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED)
        self.assertTrue(Ed25519Blake2b.PointClass() is Ed25519Point)
        self.assertTrue(Ed25519Blake2b.PublicKeyClass() is Ed25519Blake2bPublicKey)
        self.assertTrue(Ed25519Blake2b.PrivateKeyClass() is Ed25519Blake2bPrivateKey)

        self.assertEqual(Ed25519Blake2bPublicKey.CurveType(), EllipticCurveTypes.ED25519_BLAKE2B)
        self.assertEqual(Ed25519Blake2bPrivateKey.CurveType(), EllipticCurveTypes.ED25519_BLAKE2B)

        self.assertEqual(Ed25519Blake2bPublicKey.CompressedLength(), 33)
        self.assertEqual(Ed25519Blake2bPublicKey.UncompressedLength(), 33)
        self.assertEqual(Ed25519Blake2bPrivateKey.Length(), 32)

        self.assertTrue(isinstance(Ed25519Blake2bPublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)).UnderlyingObject(), ed25519_blake2b.VerifyingKey))
        self.assertTrue(isinstance(Ed25519Blake2bPublicKey(binascii.unhexlify(TEST_ED25519_UNCOMPR_PUB_KEY)).UnderlyingObject(), ed25519_blake2b.VerifyingKey))
        self.assertTrue(isinstance(Ed25519Blake2bPrivateKey(binascii.unhexlify(TEST_ED25519_PRIV_KEY)).UnderlyingObject(), ed25519_blake2b.SigningKey))

    # Test Nist256p1 class
    def test_nist256p1(self):
        self.assertEqual(Nist256p1.Name(), "Nist256p1")
        self.assertEqual(Nist256p1.Order(), generator_256.order())
        self.assertEqual(Nist256p1.Generator().X(), generator_256.x())
        self.assertEqual(Nist256p1.Generator().Y(), generator_256.y())
        self.assertEqual(Nist256p1.Generator().Order(), generator_256.order())
        self.assertTrue(Nist256p1.PointClass() is Nist256p1Point)
        self.assertTrue(Nist256p1.PublicKeyClass() is Nist256p1PublicKey)
        self.assertTrue(Nist256p1.PrivateKeyClass() is Nist256p1PrivateKey)

        self.assertEqual(Nist256p1PublicKey.CurveType(), EllipticCurveTypes.NIST256P1)
        self.assertEqual(Nist256p1PrivateKey.CurveType(), EllipticCurveTypes.NIST256P1)

        self.assertEqual(Nist256p1PublicKey.CompressedLength(), 33)
        self.assertEqual(Nist256p1PublicKey.UncompressedLength(), 65)
        self.assertEqual(Nist256p1PrivateKey.Length(), 32)

        self.assertTrue(isinstance(Nist256p1.Generator().UnderlyingObject(), ellipticcurve.PointJacobi))
        self.assertTrue(isinstance(Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_COMPR_PUB_KEY)).UnderlyingObject(), ecdsa.VerifyingKey))
        self.assertTrue(isinstance(Nist256p1PublicKey(binascii.unhexlify(TEST_NIST256P1_UNCOMPR_PUB_KEY)).UnderlyingObject(), ecdsa.VerifyingKey))
        self.assertTrue(isinstance(Nist256p1PrivateKey(binascii.unhexlify(TEST_NIST256P1_PRIV_KEY)).UnderlyingObject(), ecdsa.SigningKey))

    # Test Secp256k1 class
    def test_secp256k1(self):
        self.assertEqual(Secp256k1.Name(), "Secp256k1")
        self.assertEqual(Secp256k1.Order(), generator_secp256k1.order())
        self.assertEqual(Secp256k1.Generator().X(), generator_secp256k1.x())
        self.assertEqual(Secp256k1.Generator().Y(), generator_secp256k1.y())
        self.assertEqual(Secp256k1.Generator().Order(), generator_secp256k1.order())
        self.assertTrue(Secp256k1.PointClass() is Secp256k1Point)
        self.assertTrue(Secp256k1.PublicKeyClass() is Secp256k1PublicKey)
        self.assertTrue(Secp256k1.PrivateKeyClass() is Secp256k1PrivateKey)

        self.assertEqual(Secp256k1PublicKey.CurveType(), EllipticCurveTypes.SECP256K1)
        self.assertEqual(Secp256k1PrivateKey.CurveType(), EllipticCurveTypes.SECP256K1)

        self.assertEqual(Secp256k1PublicKey.CompressedLength(), 33)
        self.assertEqual(Secp256k1PublicKey.UncompressedLength(), 65)
        self.assertEqual(Secp256k1PrivateKey.Length(), 32)

        self.assertTrue(isinstance(Secp256k1.Generator().UnderlyingObject(), ellipticcurve.PointJacobi))
        self.assertTrue(isinstance(Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_COMPR_PUB_KEY)).UnderlyingObject(), ecdsa.VerifyingKey))
        self.assertTrue(isinstance(Secp256k1PublicKey(binascii.unhexlify(TEST_SECP256K1_UNCOMPR_PUB_KEY)).UnderlyingObject(), ecdsa.VerifyingKey))
        self.assertTrue(isinstance(Secp256k1PrivateKey(binascii.unhexlify(TEST_SECP256K1_PRIV_KEY)).UnderlyingObject(), ecdsa.SigningKey))

    # Test invalid public keys
    def test_invalid_pub_keys(self):
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Ed25519PublicKey, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519Blake2bPublicKey, binascii.unhexlify(test))
            self.assertFalse(Ed25519PublicKey.IsValid(binascii.unhexlify(test)))
            self.assertFalse(Ed25519Blake2bPublicKey.IsValid(binascii.unhexlify(test)))

        for test in TEST_VECT_NIST256P1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Nist256p1PublicKey, binascii.unhexlify(test))
            self.assertFalse(Nist256p1PublicKey.IsValid(binascii.unhexlify(test)))

        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Secp256k1PublicKey, binascii.unhexlify(test))
            self.assertFalse(Secp256k1PublicKey.IsValid(binascii.unhexlify(test)))

    # Test invalid private keys
    def test_invalid_priv_keys(self):
        for test in TEST_VECT_ED25519_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Ed25519PrivateKey, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519Blake2bPrivateKey, binascii.unhexlify(test))
            self.assertFalse(Ed25519PrivateKey.IsValid(binascii.unhexlify(test)))
            self.assertFalse(Ed25519Blake2bPrivateKey.IsValid(binascii.unhexlify(test)))

        for test in TEST_VECT_NIST256P1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Nist256p1PrivateKey, binascii.unhexlify(test))
            self.assertFalse(Nist256p1PrivateKey.IsValid(binascii.unhexlify(test)))

        for test in TEST_VECT_SECP256K1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Secp256k1PrivateKey, binascii.unhexlify(test))
            self.assertFalse(Secp256k1PrivateKey.IsValid(binascii.unhexlify(test)))
