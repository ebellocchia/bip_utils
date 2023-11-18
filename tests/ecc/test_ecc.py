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

import coincurve
import ecdsa
import ed25519_blake2b
from ecdsa import ellipticcurve
from ecdsa.ecdsa import generator_256, generator_secp256k1
from nacl import signing

from bip_utils import (
    DataBytes, Ed25519, Ed25519Blake2b, Ed25519Blake2bPoint, Ed25519Blake2bPrivateKey, Ed25519Blake2bPublicKey,
    Ed25519Kholaw, Ed25519KholawPoint, Ed25519KholawPrivateKey, Ed25519KholawPublicKey, Ed25519Monero,
    Ed25519MoneroPoint, Ed25519MoneroPrivateKey, Ed25519MoneroPublicKey, Ed25519Point, Ed25519PrivateKey,
    Ed25519PublicKey, EllipticCurveGetter, EllipticCurveTypes, Nist256p1, Nist256p1Point, Nist256p1PrivateKey,
    Nist256p1PublicKey, Secp256k1, Secp256k1Point, Secp256k1PrivateKey, Secp256k1PublicKey, Sr25519, Sr25519Point,
    Sr25519PrivateKey, Sr25519PublicKey
)
from bip_utils.ecc.conf import EccConf
from bip_utils.utils.misc import IntegerUtils


# ed25519 order and generator
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_GENERATOR_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
ED25519_GENERATOR_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960

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

# Tests for ed25519 invalid public keys
TEST_VECT_ED25519_PUB_KEY_INVALID = [
    # Public key that doesn't lie on the curve
    b"dbfe097cbed0f8f10d8980e51c92f29aaea5b69e4e4fd243f41bedb3f73b8756",
    # Public key with valid length but wrong version
    b"01e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547",
    # Public keys with invalid length
    b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a6149954711",
    b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a6149",
]

# Tests for nist256p1 invalid public keys (add public key that doesn't lie on the curve)
TEST_VECT_NIST256P1_PUB_KEY_INVALID = TEST_VECT_ECDSA_PUB_KEY_INVALID + [
    b"d24cb27bce768be8e037c48d1f03d4bd641fa6d212738f61d19677fa08385202"
]
# Tests for secp256k1 invalid public keys (add public key that doesn't lie on the curve)
TEST_VECT_SECP256K1_PUB_KEY_INVALID = TEST_VECT_ECDSA_PUB_KEY_INVALID + [
    b"02343fd9a30542d798106de1c5a62d4403c8af7c842e11badc578d21eabcf4b5a6"
]
# Tests for sr25519 invalid public keys
TEST_VECT_SR25519_PUB_KEY_INVALID = [
    # Public keys with invalid length
    b"e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a6149954711",
    b"e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a614995",
]

# Private keys with invalid lengths
TEST_VECT_PRIV_KEY_INVALID_LEN = [
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e",
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e71d0",
]

# Tests for ed25519 invalid private keys
TEST_VECT_ED25519_PRIV_KEY_INVALID = TEST_VECT_PRIV_KEY_INVALID_LEN

# Tests for ed25519-monero invalid private keys (add key equal to curve order)
TEST_VECT_ED25519_MONERO_PRIV_KEY_INVALID = TEST_VECT_PRIV_KEY_INVALID_LEN + [
    binascii.hexlify(IntegerUtils.ToBytes(Ed25519Monero.Order(), bytes_num=32, endianness="little")),
]

# Tests for nist256p1 invalid private keys (add zero key and key equal to curve order)
TEST_VECT_NIST256P1_PRIV_KEY_INVALID = TEST_VECT_PRIV_KEY_INVALID_LEN + [
    b"0000000000000000000000000000000000000000000000000000000000000000",
    binascii.hexlify(IntegerUtils.ToBytes(Nist256p1.Order(), bytes_num=32)),
]
# Tests for secp256k1 invalid private keys (add zero key and key equal to curve order)
TEST_VECT_SECP256K1_PRIV_KEY_INVALID = TEST_VECT_PRIV_KEY_INVALID_LEN + [
    b"0000000000000000000000000000000000000000000000000000000000000000",
    binascii.hexlify(IntegerUtils.ToBytes(Secp256k1.Order(), bytes_num=32)),
]

# Tests for sr25519 invalid private keys
TEST_VECT_SR25519_PRIV_KEY_INVALID = [
    # Private keys with invalid length
    b"2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616df",
    b"2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd802",
]

# Some valid ed25519 keys and points
TEST_ED25519_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"007d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c")
TEST_ED25519_UNCOMPR_PUB_KEY_BYTES = TEST_ED25519_COMPR_PUB_KEY_BYTES
TEST_ED25519_PRIV_KEY_BYTES = binascii.unhexlify(b"63326e09d412622906496bdde342b4a60410b3f48db5e74a27bfc1b0b044f80b")
TEST_ED25519_POINT_COORD = {"x": 9544908692706232050418921582846632277899217119854710143221364991731932531808,
                            "y": 42022063302689642893531488676382080543224379794475185917604557437515478359677}
TEST_ED25519_POINT_COORD_ADD = {"x": 55141681421452555293909900571285759672225843830785085368623058512752097552086,
                                "y": 55661007266727711625639119634001223501040176472020818523053744363278410546097}
TEST_ED25519_POINT_COORD_MUL = TEST_ED25519_POINT_COORD_ADD
TEST_ED25519_POINT_DEC_BYTES = binascii.unhexlify(b"600c7ff2f2378b3063e0f014ad40f46277a8cd389f6457ebf201af4e143a1a157d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c")
TEST_ED25519_POINT_ENC_BYTES = binascii.unhexlify(b"7d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c")

TEST_ED25519_PUB_KEY = Ed25519PublicKey.FromBytes(TEST_ED25519_COMPR_PUB_KEY_BYTES)
TEST_ED25519_PRIV_KEY = Ed25519PrivateKey.FromBytes(TEST_ED25519_PRIV_KEY_BYTES)
TEST_ED25519_POINT = Ed25519Point.FromCoordinates(TEST_ED25519_POINT_COORD["x"], TEST_ED25519_POINT_COORD["y"])

# Some valid ed25519-blake2b keys and points
TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"00cb8638e89ee650fdd09dc3b3342940e52598b06e3af81597471a087651875491")
TEST_ED25519_BLAKE2B_UNCOMPR_PUB_KEY_BYTES = TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES
TEST_ED25519_BLAKE2B_PRIV_KEY_BYTES = TEST_ED25519_PRIV_KEY_BYTES
TEST_ED25519_BLAKE2B_COORD_POINT = {"x": 48294182392756967208697837273234399312104812383024614014757224045799169481421,
                                    "y": 7838667511299593307117012662349698472015960877655170347921379664136072890059}

TEST_ED25519_BLAKE2B_PUB_KEY = Ed25519Blake2bPublicKey.FromBytes(TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)
TEST_ED25519_BLAKE2B_PRIV_KEY = Ed25519Blake2bPrivateKey.FromBytes(TEST_ED25519_BLAKE2B_PRIV_KEY_BYTES)
TEST_ED25519_BLAKE2B_POINT = Ed25519Blake2bPoint.FromCoordinates(TEST_ED25519_BLAKE2B_COORD_POINT["x"], TEST_ED25519_BLAKE2B_COORD_POINT["y"])

# Some valid ed25519-kholaw keys
TEST_ED25519_KHOLAW_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"001f4dc49e82a836dfd380925261315f213adef7aae3f34de699d7f32ba0982c6d")
TEST_ED25519_KHOLAW_UNCOMPR_PUB_KEY_BYTES = TEST_ED25519_KHOLAW_COMPR_PUB_KEY_BYTES
TEST_ED25519_KHOLAW_PRIV_KEY_BYTES = binascii.unhexlify(b"1075ab5e3fcedcb69eef77974b314cc0cbc163c01a0c354989dc70b8789a194fb52396acaa97135c2f2f042e4181da5fbe92b8350d00055bee42eccf3088fd24")

TEST_ED25519_KHOLAW_PUB_KEY = Ed25519KholawPublicKey.FromBytes(TEST_ED25519_KHOLAW_COMPR_PUB_KEY_BYTES)
TEST_ED25519_KHOLAW_PRIV_KEY = Ed25519KholawPrivateKey.FromBytes(TEST_ED25519_KHOLAW_PRIV_KEY_BYTES)

# Some valid ed25519-monero keys and points
TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"5432db2c5e3953afda4184e534a25abe78bd08027d9c048d9c16c15fd73280e6")
TEST_ED25519_MONERO_UNCOMPR_PUB_KEY_BYTES = TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES
TEST_ED25519_MONERO_PRIV_KEY_BYTES = TEST_ED25519_PRIV_KEY_BYTES
TEST_ED25519_MONERO_POINT_COORD = {"x": 16674457676716737978374862850521939870908941361163415909647017870848613367519,
                                   "y": 46362417873574777412568930969947358133147671210501021588337420811295298105940}

TEST_ED25519_MONERO_PUB_KEY = Ed25519MoneroPublicKey.FromBytes(TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES)
TEST_ED25519_MONERO_PRIV_KEY = Ed25519MoneroPrivateKey.FromBytes(TEST_ED25519_MONERO_PRIV_KEY_BYTES)
TEST_ED25519_MONERO_POINT = Ed25519MoneroPoint.FromCoordinates(TEST_ED25519_MONERO_POINT_COORD["x"], TEST_ED25519_MONERO_POINT_COORD["y"])

# Some valid nist256p1 keys and points
TEST_NIST256P1_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b")
TEST_NIST256P1_UNCOMPR_PUB_KEY_BYTES = binascii.unhexlify(b"048ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b465656d4dd23293a66bbbd3cc07cf6e5b1cd3b81d8e3da4eed050ac0ab2094b9")
TEST_NIST256P1_PRIV_KEY_BYTES = binascii.unhexlify(b"e44c51393e98a691439f74c2060138fa2bcefae59ab277bd81907c93fb16fce1")
TEST_NIST256P1_POINT_COORD = {"x": 64511146437640532869164237123971144495620316712208575072439516305921182895195,
                              "y": 31814447537382586537576639307337099269020393742089100496617531967175387026617}
TEST_NIST256P1_POINT_COORD_ADD = {"x": 101370444989464769337019234113187919586549255451863198632358447242825043882751,
                                  "y": 96679656738774927550763413778994915607472627190911082265431331813273377117362}
TEST_NIST256P1_POINT_COORD_MUL = TEST_NIST256P1_POINT_COORD_ADD
TEST_NIST256P1_POINT_DEC_BYTES = binascii.unhexlify(b"8ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b465656d4dd23293a66bbbd3cc07cf6e5b1cd3b81d8e3da4eed050ac0ab2094b9")
TEST_NIST256P1_POINT_ENC_BYTES = binascii.unhexlify(b"038ea003d38b3f2043e681f06f56b3864d28d73b4f243aee90ed04a28dbc058c5b")

TEST_NIST256P1_PUB_KEY = Nist256p1PublicKey.FromBytes(TEST_NIST256P1_COMPR_PUB_KEY_BYTES)
TEST_NIST256P1_PRIV_KEY = Nist256p1PrivateKey.FromBytes(TEST_NIST256P1_PRIV_KEY_BYTES)
TEST_NIST256P1_POINT = Nist256p1Point.FromCoordinates(TEST_NIST256P1_POINT_COORD["x"], TEST_NIST256P1_POINT_COORD["y"])

# Some valid secp256k1 keys and points
TEST_SECP256K1_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"02c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4")
TEST_SECP256K1_UNCOMPR_PUB_KEY_BYTES = binascii.unhexlify(b"04c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4ec9654b17e30a8a5232078201ecf5cc702dfbb70266aecf16b1f81d85e6b9942")
TEST_SECP256K1_PRIV_KEY_BYTES = binascii.unhexlify(b"e1d36931d581b4dcae0bb03929adcfb5ab0cdc0f4886ff6c5098591636ace214")
TEST_SECP256K1_POINT_COORD = {"x": 88568707669548495476516508095445138344657010992834487537871095020828542384628,
                              "y": 107011443857260681605663973889402727500845015180707970416758298978829074143554}
TEST_SECP256K1_POINT_COORD_ADD = {"x": 36055427468220068554092197997262360511679559617381195682414059417211150654731,
                                  "y": 35614013837322639151401845680153599308855232143046454444952007884320857835400}
TEST_SECP256K1_POINT_COORD_MUL = TEST_SECP256K1_POINT_COORD_ADD
TEST_SECP256K1_POINT_DEC_BYTES = binascii.unhexlify(b"c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4ec9654b17e30a8a5232078201ecf5cc702dfbb70266aecf16b1f81d85e6b9942")
TEST_SECP256K1_POINT_ENC_BYTES = binascii.unhexlify(b"02c3d01cb07697dc5105013bea2e73a896b6019ec3c5ea2b97dba14ae4456439f4")

TEST_SECP256K1_PUB_KEY = Secp256k1PublicKey.FromBytes(TEST_SECP256K1_COMPR_PUB_KEY_BYTES)
TEST_SECP256K1_PRIV_KEY = Secp256k1PrivateKey.FromBytes(TEST_SECP256K1_PRIV_KEY_BYTES)
TEST_SECP256K1_POINT = Secp256k1Point.FromCoordinates(TEST_SECP256K1_POINT_COORD["x"], TEST_SECP256K1_POINT_COORD["y"])

# Some valid sr25519 keys
TEST_SR25519_COMPR_PUB_KEY_BYTES = binascii.unhexlify(b"66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972")
TEST_SR25519_UNCOMPR_PUB_KEY_BYTES = TEST_SR25519_COMPR_PUB_KEY_BYTES
TEST_SR25519_PRIV_KEY_BYTES = binascii.unhexlify(b"2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8")

TEST_SR25519_PUB_KEY = Sr25519PublicKey.FromBytes(TEST_SR25519_COMPR_PUB_KEY_BYTES)
TEST_SR25519_PRIV_KEY = Sr25519PrivateKey.FromBytes(TEST_SR25519_PRIV_KEY_BYTES)


#
# Tests
#
class EccTests(unittest.TestCase):
    # Test elliptic curve getter
    def test_elliptic_curve_getter(self):
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.ED25519) is Ed25519)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.ED25519_BLAKE2B) is Ed25519Blake2b)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.NIST256P1) is Nist256p1)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.SECP256K1) is Secp256k1)
        self.assertTrue(EllipticCurveGetter.FromType(EllipticCurveTypes.SR25519) is Sr25519)
        self.assertRaises(TypeError, EllipticCurveGetter.FromType, 0)

    # Test Ed25519 class
    def test_ed25519(self):
        # Curve
        self.assertEqual(Ed25519.Name(), "Ed25519")
        self.assertEqual(Ed25519.Order(), ED25519_ORDER)
        self.assertEqual(Ed25519.Generator().X(), ED25519_GENERATOR_X)
        self.assertEqual(Ed25519.Generator().Y(), ED25519_GENERATOR_Y)
        self.assertTrue(Ed25519.PointClass() is Ed25519Point)
        self.assertTrue(Ed25519.PublicKeyClass() is Ed25519PublicKey)
        self.assertTrue(Ed25519.PrivateKeyClass() is Ed25519PrivateKey)

        # Public key
        self.assertEqual(Ed25519PublicKey.CurveType(), EllipticCurveTypes.ED25519)
        self.assertEqual(Ed25519PublicKey.CompressedLength(), 33)
        self.assertEqual(Ed25519PublicKey.UncompressedLength(), 33)

        # From compressed
        pub_key = Ed25519PublicKey.FromBytes(TEST_ED25519_COMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.Point(), Ed25519Point))
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.UnderlyingObject(), signing.VerifyKey))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_UNCOMPR_PUB_KEY_BYTES)
        # From uncompressed
        pub_key = Ed25519PublicKey.FromBytes(TEST_ED25519_UNCOMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_UNCOMPR_PUB_KEY_BYTES)
        # From point
        pub_key = Ed25519PublicKey.FromPoint(Ed25519Point.FromCoordinates(TEST_ED25519_POINT_COORD["x"],
                                                                          TEST_ED25519_POINT_COORD["y"]))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_UNCOMPR_PUB_KEY_BYTES)

        # Private key
        self.assertEqual(Ed25519PrivateKey.CurveType(), EllipticCurveTypes.ED25519)
        self.assertEqual(Ed25519PrivateKey.Length(), 32)

        priv_key = Ed25519PrivateKey.FromBytes(TEST_ED25519_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.PublicKey(), Ed25519PublicKey))
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), signing.SigningKey))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_ED25519_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_ED25519_COMPR_PUB_KEY_BYTES)

        #
        # Point
        #
        self.assertEqual(Ed25519Point.CurveType(), EllipticCurveTypes.ED25519)
        self.assertEqual(Ed25519Point.CoordinateLength(), 32)

        point = pub_key.Point()
        self.assertTrue(isinstance(point.Raw(), DataBytes))
        self.assertTrue(isinstance(point.RawDecoded(), DataBytes))
        self.assertTrue(isinstance(point.RawEncoded(), DataBytes))
        self.assertTrue(isinstance(point.UnderlyingObject(), bytes))
        self.assertEqual(point.X(), TEST_ED25519_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_ED25519_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_ED25519_POINT_DEC_BYTES)
        self.assertEqual(point.RawDecoded().ToBytes(), TEST_ED25519_POINT_DEC_BYTES)
        self.assertEqual(point.RawEncoded().ToBytes(), TEST_ED25519_POINT_ENC_BYTES)

        # Addition
        point_add = point + point
        self.assertEqual(point_add.X(), TEST_ED25519_POINT_COORD_ADD["x"])
        self.assertEqual(point_add.Y(), TEST_ED25519_POINT_COORD_ADD["y"])

        # Multiplication
        point_mul = point * 2
        self.assertEqual(point_mul.X(), TEST_ED25519_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_ED25519_POINT_COORD_MUL["y"])

        # Reverse multiplication
        point_mul = 2 * point
        self.assertEqual(point_mul.X(), TEST_ED25519_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_ED25519_POINT_COORD_MUL["y"])

        # From bytes
        point = Ed25519Point.FromBytes(TEST_ED25519_POINT_DEC_BYTES)
        self.assertEqual(point.X(), TEST_ED25519_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_ED25519_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_ED25519_POINT_DEC_BYTES)

        point = Ed25519Point.FromBytes(TEST_ED25519_POINT_ENC_BYTES)
        self.assertEqual(point.X(), TEST_ED25519_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_ED25519_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_ED25519_POINT_DEC_BYTES)

    # Test Ed25519-Blake2b class
    def test_ed25519_blake2b(self):
        # Curve
        self.assertEqual(Ed25519Blake2b.Name(), "Ed25519-Blake2b")
        self.assertEqual(Ed25519Blake2b.Order(), ED25519_ORDER)
        self.assertEqual(Ed25519Blake2b.Generator().X(), ED25519_GENERATOR_X)
        self.assertEqual(Ed25519Blake2b.Generator().Y(), ED25519_GENERATOR_Y)
        self.assertTrue(Ed25519Blake2b.PointClass() is Ed25519Blake2bPoint)
        self.assertTrue(Ed25519Blake2b.PublicKeyClass() is Ed25519Blake2bPublicKey)
        self.assertTrue(Ed25519Blake2b.PrivateKeyClass() is Ed25519Blake2bPrivateKey)

        # Public key
        self.assertEqual(Ed25519Blake2bPublicKey.CurveType(), EllipticCurveTypes.ED25519_BLAKE2B)
        self.assertEqual(Ed25519Blake2bPublicKey.CompressedLength(), 33)
        self.assertEqual(Ed25519Blake2bPublicKey.UncompressedLength(), 33)

        # From compressed
        pub_key = Ed25519Blake2bPublicKey.FromBytes(TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_BLAKE2B_UNCOMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.Point(), Ed25519Blake2bPoint))
        self.assertTrue(isinstance(pub_key.UnderlyingObject(), ed25519_blake2b.VerifyingKey))
        # From uncompressed
        pub_key = Ed25519Blake2bPublicKey.FromBytes(TEST_ED25519_BLAKE2B_UNCOMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_BLAKE2B_UNCOMPR_PUB_KEY_BYTES)
        # From point
        pub_key = Ed25519Blake2bPublicKey.FromPoint(Ed25519Blake2bPoint.FromCoordinates(TEST_ED25519_BLAKE2B_COORD_POINT["x"],
                                                                                        TEST_ED25519_BLAKE2B_COORD_POINT["y"]))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_BLAKE2B_UNCOMPR_PUB_KEY_BYTES)

        # Private key
        self.assertEqual(Ed25519Blake2bPrivateKey.CurveType(), EllipticCurveTypes.ED25519_BLAKE2B)
        self.assertEqual(Ed25519Blake2bPrivateKey.Length(), 32)

        priv_key = Ed25519Blake2bPrivateKey.FromBytes(TEST_ED25519_BLAKE2B_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.PublicKey(), Ed25519Blake2bPublicKey))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), ed25519_blake2b.SigningKey))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_ED25519_BLAKE2B_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_ED25519_BLAKE2B_COMPR_PUB_KEY_BYTES)

        # No need to test point, same of ed25519
        self.assertTrue(issubclass(Ed25519Blake2bPoint, Ed25519Point))
        self.assertEqual(Ed25519Blake2bPoint.CurveType(), EllipticCurveTypes.ED25519_BLAKE2B)

    # Test Ed25519-Kholaw class
    def test_ed25519_kholaw(self):
        # Curve
        self.assertEqual(Ed25519Kholaw.Name(), "Ed25519-Kholaw")
        self.assertEqual(Ed25519Kholaw.Order(), ED25519_ORDER)
        self.assertEqual(Ed25519Kholaw.Generator().X(), ED25519_GENERATOR_X)
        self.assertEqual(Ed25519Kholaw.Generator().Y(), ED25519_GENERATOR_Y)
        self.assertTrue(Ed25519Kholaw.PointClass() is Ed25519KholawPoint)
        self.assertTrue(Ed25519Kholaw.PublicKeyClass() is Ed25519KholawPublicKey)
        self.assertTrue(Ed25519Kholaw.PrivateKeyClass() is Ed25519KholawPrivateKey)

        # No need to test public key, same of ed25519
        self.assertTrue(issubclass(Ed25519KholawPublicKey, Ed25519PublicKey))
        self.assertEqual(Ed25519KholawPublicKey.CurveType(), EllipticCurveTypes.ED25519_KHOLAW)
        pub_key = Ed25519KholawPublicKey.FromBytes(TEST_ED25519_KHOLAW_COMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.Point(), Ed25519KholawPoint))

        # Private key
        self.assertRaises(TypeError, Ed25519KholawPrivateKey, 0, b"")
        self.assertRaises(ValueError, Ed25519KholawPrivateKey, TEST_ED25519_PRIV_KEY, b"")
        self.assertEqual(Ed25519KholawPrivateKey.CurveType(), EllipticCurveTypes.ED25519_KHOLAW)
        self.assertEqual(Ed25519KholawPrivateKey.Length(), 64)

        priv_key = Ed25519KholawPrivateKey.FromBytes(TEST_ED25519_KHOLAW_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.PublicKey(), Ed25519KholawPublicKey))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), signing.SigningKey))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_ED25519_KHOLAW_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_ED25519_KHOLAW_COMPR_PUB_KEY_BYTES)

        # No need to test point, same of ed25519
        self.assertTrue(issubclass(Ed25519KholawPoint, Ed25519Point))
        self.assertEqual(Ed25519KholawPoint.CurveType(), EllipticCurveTypes.ED25519_KHOLAW)

    # Test Ed25519-Monero class
    def test_ed25519_monero(self):
        # Curve
        self.assertEqual(Ed25519Monero.Name(), "Ed25519-Monero")
        self.assertEqual(Ed25519Monero.Order(), ED25519_ORDER)
        self.assertEqual(Ed25519Monero.Generator().X(), ED25519_GENERATOR_X)
        self.assertEqual(Ed25519Monero.Generator().Y(), ED25519_GENERATOR_Y)
        self.assertTrue(Ed25519Monero.PointClass() is Ed25519MoneroPoint)
        self.assertTrue(Ed25519Monero.PublicKeyClass() is Ed25519MoneroPublicKey)
        self.assertTrue(Ed25519Monero.PrivateKeyClass() is Ed25519MoneroPrivateKey)

        # Almost the same of ed25519, only lengths change
        self.assertTrue(issubclass(Ed25519MoneroPublicKey, Ed25519PublicKey))
        self.assertEqual(Ed25519MoneroPublicKey.CurveType(), EllipticCurveTypes.ED25519_MONERO)
        self.assertEqual(Ed25519MoneroPublicKey.CompressedLength(), 32)
        self.assertEqual(Ed25519MoneroPublicKey.UncompressedLength(), 32)

        pub_key = Ed25519MoneroPublicKey.FromBytes(TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_ED25519_MONERO_UNCOMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.Point(), Ed25519MoneroPoint))

        # Almost the same of ed25519, only public key computation changes
        self.assertTrue(issubclass(Ed25519MoneroPrivateKey, Ed25519PrivateKey))
        self.assertEqual(Ed25519MoneroPrivateKey.CurveType(), EllipticCurveTypes.ED25519_MONERO)

        priv_key = Ed25519MoneroPrivateKey.FromBytes(TEST_ED25519_MONERO_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.PublicKey(), Ed25519MoneroPublicKey))
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_ED25519_MONERO_COMPR_PUB_KEY_BYTES)

        # No need to test point, same of ed25519
        self.assertTrue(issubclass(Ed25519MoneroPoint, Ed25519Point))
        self.assertEqual(Ed25519MoneroPoint.CurveType(), EllipticCurveTypes.ED25519_MONERO)

    # Test Nist256p1 class
    def test_nist256p1(self):
        # Curve
        self.assertEqual(Nist256p1.Name(), "Nist256p1")
        self.assertEqual(Nist256p1.Order(), generator_256.order())
        self.assertEqual(Nist256p1.Generator().X(), generator_256.x())
        self.assertEqual(Nist256p1.Generator().Y(), generator_256.y())
        self.assertTrue(Nist256p1.PointClass() is Nist256p1Point)
        self.assertTrue(Nist256p1.PublicKeyClass() is Nist256p1PublicKey)
        self.assertTrue(Nist256p1.PrivateKeyClass() is Nist256p1PrivateKey)

        #
        # Public key
        #
        self.assertEqual(Nist256p1PublicKey.CurveType(), EllipticCurveTypes.NIST256P1)
        self.assertEqual(Nist256p1PublicKey.CompressedLength(), 33)
        self.assertEqual(Nist256p1PublicKey.UncompressedLength(), 65)

        # From compressed
        pub_key = Nist256p1PublicKey.FromBytes(TEST_NIST256P1_COMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.Point(), Nist256p1Point))
        self.assertTrue(isinstance(pub_key.UnderlyingObject(), ecdsa.VerifyingKey))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_NIST256P1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_NIST256P1_UNCOMPR_PUB_KEY_BYTES)
        # From uncompressed
        pub_key = Nist256p1PublicKey.FromBytes(TEST_NIST256P1_UNCOMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_NIST256P1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_NIST256P1_UNCOMPR_PUB_KEY_BYTES)

        # From point
        pub_key = Nist256p1PublicKey.FromPoint(Nist256p1Point.FromCoordinates(TEST_NIST256P1_POINT_COORD["x"],
                                                                              TEST_NIST256P1_POINT_COORD["y"]))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_NIST256P1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_NIST256P1_UNCOMPR_PUB_KEY_BYTES)

        #
        # Private key
        #
        self.assertEqual(Nist256p1PrivateKey.CurveType(), EllipticCurveTypes.NIST256P1)
        self.assertEqual(Nist256p1PrivateKey.Length(), 32)

        priv_key = Nist256p1PrivateKey.FromBytes(TEST_NIST256P1_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.PublicKey(), Nist256p1PublicKey))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), ecdsa.SigningKey))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_NIST256P1_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_NIST256P1_COMPR_PUB_KEY_BYTES)

        #
        # Point
        #
        self.assertEqual(Nist256p1Point.CurveType(), EllipticCurveTypes.NIST256P1)
        self.assertEqual(Nist256p1Point.CoordinateLength(), 32)

        point = pub_key.Point()
        self.assertTrue(isinstance(point.Raw(), DataBytes))
        self.assertTrue(isinstance(point.RawDecoded(), DataBytes))
        self.assertTrue(isinstance(point.RawEncoded(), DataBytes))
        self.assertTrue(isinstance(point.UnderlyingObject(), ellipticcurve.PointJacobi))
        self.assertEqual(point.X(), TEST_NIST256P1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_NIST256P1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_NIST256P1_POINT_DEC_BYTES)
        self.assertEqual(point.RawDecoded().ToBytes(), TEST_NIST256P1_POINT_DEC_BYTES)
        self.assertEqual(point.RawEncoded().ToBytes(), TEST_NIST256P1_POINT_ENC_BYTES)

        # Addition
        point_add = point + point
        self.assertEqual(point_add.X(), TEST_NIST256P1_POINT_COORD_ADD["x"])
        self.assertEqual(point_add.Y(), TEST_NIST256P1_POINT_COORD_ADD["y"])

        # Multiplication
        point_mul = point * 2
        self.assertEqual(point_mul.X(), TEST_NIST256P1_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_NIST256P1_POINT_COORD_MUL["y"])

        # Reverse multiplication
        point_mul = 2 * point
        self.assertEqual(point_mul.X(), TEST_NIST256P1_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_NIST256P1_POINT_COORD_MUL["y"])

        # From bytes
        point = Nist256p1Point.FromBytes(TEST_NIST256P1_POINT_DEC_BYTES)
        self.assertEqual(point.X(), TEST_NIST256P1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_NIST256P1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_NIST256P1_POINT_DEC_BYTES)

        point = Nist256p1Point.FromBytes(TEST_NIST256P1_POINT_ENC_BYTES)
        self.assertEqual(point.X(), TEST_NIST256P1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_NIST256P1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_NIST256P1_POINT_DEC_BYTES)

    # Test Secp256k1 class
    def test_secp256k1(self):
        # Curve
        self.assertEqual(Secp256k1.Name(), "Secp256k1")
        self.assertEqual(Secp256k1.Order(), generator_secp256k1.order())
        self.assertEqual(Secp256k1.Generator().X(), generator_secp256k1.x())
        self.assertEqual(Secp256k1.Generator().Y(), generator_secp256k1.y())
        self.assertTrue(Secp256k1.PointClass() is Secp256k1Point)
        self.assertTrue(Secp256k1.PublicKeyClass() is Secp256k1PublicKey)
        self.assertTrue(Secp256k1.PrivateKeyClass() is Secp256k1PrivateKey)

        #
        # Public key
        #
        self.assertEqual(Secp256k1PublicKey.CurveType(), EllipticCurveTypes.SECP256K1)
        self.assertEqual(Secp256k1PublicKey.CompressedLength(), 33)
        self.assertEqual(Secp256k1PublicKey.UncompressedLength(), 65)

        # From compressed
        pub_key = Secp256k1PublicKey.FromBytes(TEST_SECP256K1_COMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.Point(), Secp256k1Point))
        self.assertTrue(isinstance(pub_key.UnderlyingObject(), coincurve.PublicKey if EccConf.USE_COINCURVE else ecdsa.VerifyingKey))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_SECP256K1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_SECP256K1_UNCOMPR_PUB_KEY_BYTES)
        # From uncompressed
        pub_key = Secp256k1PublicKey.FromBytes(TEST_SECP256K1_UNCOMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_SECP256K1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_SECP256K1_UNCOMPR_PUB_KEY_BYTES)

        # From point
        pub_key = Secp256k1PublicKey.FromPoint(Secp256k1Point.FromCoordinates(TEST_SECP256K1_POINT_COORD["x"],
                                                                              TEST_SECP256K1_POINT_COORD["y"]))
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_SECP256K1_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_SECP256K1_UNCOMPR_PUB_KEY_BYTES)

        #
        # Private key
        #
        self.assertEqual(Secp256k1PrivateKey.CurveType(), EllipticCurveTypes.SECP256K1)
        self.assertEqual(Secp256k1PrivateKey.Length(), 32)

        priv_key = Secp256k1PrivateKey.FromBytes(TEST_SECP256K1_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.PublicKey(), Secp256k1PublicKey))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), coincurve.PrivateKey if EccConf.USE_COINCURVE else ecdsa.SigningKey))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_SECP256K1_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_SECP256K1_COMPR_PUB_KEY_BYTES)

        #
        # Point
        #
        self.assertEqual(Secp256k1Point.CurveType(), EllipticCurveTypes.SECP256K1)
        self.assertEqual(Secp256k1Point.CoordinateLength(), 32)

        point = pub_key.Point()
        self.assertTrue(isinstance(point.Raw(), DataBytes))
        self.assertTrue(isinstance(point.RawDecoded(), DataBytes))
        self.assertTrue(isinstance(point.RawEncoded(), DataBytes))
        self.assertTrue(isinstance(point.UnderlyingObject(), coincurve.PublicKey if EccConf.USE_COINCURVE else ellipticcurve.PointJacobi))
        self.assertEqual(point.X(), TEST_SECP256K1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_SECP256K1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_SECP256K1_POINT_DEC_BYTES)
        self.assertEqual(point.RawDecoded().ToBytes(), TEST_SECP256K1_POINT_DEC_BYTES)
        self.assertEqual(point.RawEncoded().ToBytes(), TEST_SECP256K1_POINT_ENC_BYTES)

        # Addition
        point_add = point + point
        self.assertEqual(point_add.X(), TEST_SECP256K1_POINT_COORD_ADD["x"])
        self.assertEqual(point_add.Y(), TEST_SECP256K1_POINT_COORD_ADD["y"])

        # Multiplication
        point_mul = point * 2
        self.assertEqual(point_mul.X(), TEST_SECP256K1_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_SECP256K1_POINT_COORD_MUL["y"])

        # Reverse multiplication
        point_mul = 2 * point
        self.assertEqual(point_mul.X(), TEST_SECP256K1_POINT_COORD_MUL["x"])
        self.assertEqual(point_mul.Y(), TEST_SECP256K1_POINT_COORD_MUL["y"])

        # From bytes
        point = Secp256k1Point.FromBytes(TEST_SECP256K1_POINT_DEC_BYTES)
        self.assertEqual(point.X(), TEST_SECP256K1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_SECP256K1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_SECP256K1_POINT_DEC_BYTES)

        point = Secp256k1Point.FromBytes(TEST_SECP256K1_POINT_ENC_BYTES)
        self.assertEqual(point.X(), TEST_SECP256K1_POINT_COORD["x"])
        self.assertEqual(point.Y(), TEST_SECP256K1_POINT_COORD["y"])
        self.assertEqual(point.Raw().ToBytes(), TEST_SECP256K1_POINT_DEC_BYTES)

    # Test Sr25519 class
    def test_sr25519(self):
        # Curve
        self.assertEqual(Sr25519.Name(), "Sr25519")
        self.assertEqual(Sr25519.Order(), 0)
        self.assertEqual(Sr25519.Generator().X(), 0)
        self.assertEqual(Sr25519.Generator().Y(), 0)
        self.assertTrue(Sr25519.PointClass() is Sr25519Point)
        self.assertTrue(Sr25519.PublicKeyClass() is Sr25519PublicKey)
        self.assertTrue(Sr25519.PrivateKeyClass() is Sr25519PrivateKey)

        # Public key
        self.assertRaises(RuntimeError, Sr25519PublicKey.FromPoint, Sr25519Point.FromCoordinates(0, 0))
        self.assertEqual(Sr25519PublicKey.CurveType(), EllipticCurveTypes.SR25519)
        self.assertEqual(Sr25519PublicKey.CompressedLength(), 32)
        self.assertEqual(Sr25519PublicKey.UncompressedLength(), 32)

        # From compressed
        pub_key = Sr25519PublicKey.FromBytes(TEST_SR25519_COMPR_PUB_KEY_BYTES)
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.UnderlyingObject(), bytes))
        self.assertRaises(RuntimeError, pub_key.Point)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_SR25519_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_SR25519_UNCOMPR_PUB_KEY_BYTES)

        # From uncompressed
        pub_key = Sr25519PublicKey.FromBytes(TEST_SR25519_UNCOMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawCompressed().ToBytes(), TEST_SR25519_COMPR_PUB_KEY_BYTES)
        self.assertEqual(pub_key.RawUncompressed().ToBytes(), TEST_SR25519_UNCOMPR_PUB_KEY_BYTES)
        # Private key
        self.assertEqual(Sr25519PrivateKey.CurveType(), EllipticCurveTypes.SR25519)
        self.assertEqual(Sr25519PrivateKey.Length(), 64)

        priv_key = Sr25519PrivateKey.FromBytes(TEST_SR25519_PRIV_KEY_BYTES)
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        self.assertTrue(isinstance(priv_key.PublicKey(), Sr25519PublicKey))
        self.assertTrue(isinstance(priv_key.UnderlyingObject(), bytes))
        self.assertEqual(priv_key.Raw().ToBytes(), TEST_SR25519_PRIV_KEY_BYTES)
        self.assertEqual(priv_key.PublicKey().RawCompressed().ToBytes(), TEST_SR25519_COMPR_PUB_KEY_BYTES)

        # Point
        self.__test_dummy_point(Sr25519Point, EllipticCurveTypes.SR25519)

    # Test invalid public keys
    def test_invalid_pub_keys(self):
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Ed25519PublicKey.FromBytes, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519Blake2bPublicKey.FromBytes, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519KholawPublicKey.FromBytes, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519MoneroPublicKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Ed25519PublicKey.IsValidBytes(binascii.unhexlify(test)))
            self.assertFalse(Ed25519Blake2bPublicKey.IsValidBytes(binascii.unhexlify(test)))
            self.assertFalse(Ed25519KholawPublicKey.IsValidBytes(binascii.unhexlify(test)))
            self.assertFalse(Ed25519MoneroPublicKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_NIST256P1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Nist256p1PublicKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Nist256p1PublicKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Secp256k1PublicKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Secp256k1PublicKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_SR25519_PUB_KEY_INVALID:
            self.assertRaises(ValueError, Sr25519PublicKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Sr25519PublicKey.IsValidBytes(binascii.unhexlify(test)))

    # Test invalid private keys
    def test_invalid_priv_keys(self):
        for test in TEST_VECT_ED25519_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Ed25519PrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519Blake2bPrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertRaises(ValueError, Ed25519KholawPrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Ed25519PrivateKey.IsValidBytes(binascii.unhexlify(test)))
            self.assertFalse(Ed25519Blake2bPrivateKey.IsValidBytes(binascii.unhexlify(test)))
            self.assertFalse(Ed25519KholawPrivateKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_ED25519_MONERO_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Ed25519MoneroPrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Ed25519MoneroPrivateKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_NIST256P1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Nist256p1PrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Nist256p1PrivateKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_SECP256K1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Secp256k1PrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Secp256k1PrivateKey.IsValidBytes(binascii.unhexlify(test)))

        for test in TEST_VECT_SR25519_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, Sr25519PrivateKey.FromBytes, binascii.unhexlify(test))
            self.assertFalse(Sr25519PrivateKey.IsValidBytes(binascii.unhexlify(test)))

    # Test for DummyPoint
    def __test_dummy_point(self, point_cls, curve_type):
        TEST_X = 1
        TEST_Y = 2
        TEST_RAW = IntegerUtils.ToBytes(TEST_X, bytes_num=32) + IntegerUtils.ToBytes(TEST_Y, bytes_num=32)

        self.assertEqual(point_cls.CoordinateLength(), 32)
        self.assertRaises(TypeError, point_cls, 0)


        point = point_cls.FromBytes(TEST_RAW)
        self.assertTrue(isinstance(point.Raw(), DataBytes))
        self.assertTrue(isinstance(point.RawDecoded(), DataBytes))
        self.assertTrue(isinstance(point.RawEncoded(), DataBytes))
        self.assertTrue(point.UnderlyingObject() is None)
        self.assertTrue(point.CurveType() is curve_type)
        self.assertEqual(point.X(), TEST_X)
        self.assertEqual(point.Y(), TEST_Y)
        self.assertEqual(point.Raw().ToBytes(), TEST_RAW)
        self.assertEqual(point.RawDecoded().ToBytes(), TEST_RAW)
        self.assertEqual(point.RawEncoded().ToBytes(), TEST_RAW)

        point = point_cls.FromCoordinates(1, 2)
        self.assertEqual(point.X(), TEST_X)
        self.assertEqual(point.Y(), TEST_Y)
        self.assertEqual(point.Raw().ToBytes(), TEST_RAW)
        self.assertEqual(point.RawDecoded().ToBytes(), TEST_RAW)
        self.assertEqual(point.RawEncoded().ToBytes(), TEST_RAW)

        # Addition
        point_add = point + point
        self.assertEqual(point_add.X(), TEST_X + TEST_X)
        self.assertEqual(point_add.Y(), TEST_Y + TEST_Y)

        # Multiplication
        point_mul = point * 2
        self.assertEqual(point_mul.X(), TEST_X * 2)
        self.assertEqual(point_mul.Y(), TEST_Y * 2)

        # Reverse multiplication
        point_mul = 2 * point
        self.assertEqual(point_mul.X(), TEST_X * 2)
        self.assertEqual(point_mul.Y(), TEST_Y * 2)
