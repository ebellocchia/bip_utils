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
from bip_utils import (
    Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyData, Bip32KeyError, Bip32KeyIndex, Bip32PrivateKey,
    Bip32PublicKey
)
from bip_utils.bip.bip32.bip32_const import Bip32Const
from tests.ecc.test_ecc import *


# Public keys for testing
TEST_PUB_KEYS = [
    {
        "key": TEST_ED25519_PUB_KEY,
        "point": TEST_ED25519_POINT,
        "fprint": b"6ff1e466",
        "key_id": b"6ff1e46644e62d8d44ee2fffb45960d350202c4b",
        "ext": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6M92aGJUuyzo3iKu8Tb6Jq9HnFbbiyiU4QAK6jM2uTxAQH8D2z9",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PUB_KEY,
        "fprint": b"23e1ef48",
        "key_id": b"23e1ef48982188655152d7e651b754e562eb018e",
        "ext": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6MjSvvgvbUpTCdiDZv1NjVCyfZdj97RkKXsQRkzksL4xhRE3px7",
    },
    {
        "key": TEST_ED25519_KHOLAW_PUB_KEY,
        "fprint": b"71342f63",
        "key_id": b"71342f6318fa02b2a9c637705f29161176cba7f5",
        "ext": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LRbngVJ7HbzwAqNFFcXRzcgQpEweodBwYUtnKyByuf4Qbtn4yn",
    },
    {
        "key": TEST_ED25519_MONERO_PUB_KEY,
        "point": TEST_ED25519_MONERO_POINT,
        "fprint": b"41a4a2c0",
        "key_id": b"41a4a2c0cfa0c22ee6b00a6033fff32bd7aa9959",
        "ext": "Deb7pNXSbX7qSvc2e43XLxrU4Wbif71fzakq2ecQpZSkGDbATEXFMJkjpWRoUgATX3eHcbp5fSCXmS8BQ7Yk4P3L2xCtnnhj5rFET3oeLkqLHL",
    },
    {
        "key": TEST_NIST256P1_PUB_KEY,
        "point": TEST_NIST256P1_POINT,
        "fprint": b"5fa155ff",
        "key_id": b"5fa155ff09510ec6ca9dd3f8e51b06e327bf4845",
        "ext": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6T6rsRpT4yF4fz2ss6DqTdiKczA3f5aWFpMq4QND6iPeQJENNmM",
    },
    {
        "key": TEST_SECP256K1_PUB_KEY,
        "point": TEST_SECP256K1_POINT,
        "fprint": b"e168bdf4",
        "key_id": b"e168bdf4a501ed739b5a94731bd13d0044efd7c7",
        "ext": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6RZYJkUia7CG7jyT3sA25TNNT1zXNBYE2YmshUj7TZbuFCYsVZf",
    },
    {
        "key": TEST_SR25519_PUB_KEY,
        "fprint": b"7bde84a2",
        "key_id": b"7bde84a21e328728228f4fc69a24f57d85f7d1a4",
        "ext": "Deb7pNXSbX7qSvc2e43XLxrU4Wbif71fzakq2ecQpZSkGDbATEXFMJkjpWRoUpFrrfLeLKYGpWEcqZeSUxdBe1GVs4vezvdnpmQYUfu3JPRUhT",
    },
]

# Private keys for testing
TEST_PRIV_KEYS = [
    {
        "key": TEST_ED25519_PRIV_KEY,
        "ext": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9oDwUq8hbmYVXq9jRSi64zDnhjwYo5AMM7tJamccfayBLd1QF4",
    },
    {
        "key": TEST_ED25519_BLAKE2B_PRIV_KEY,
        "ext": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9oDwUq8hbmYVXq9jRSi64zDnhjwYo5AMM7tJamccfayBLd1QF4",
    },
    {
        "key": TEST_ED25519_KHOLAW_PRIV_KEY,
        "ext": "Har3K3MhV5fiuEp6zVeBb8kRY8AZbY6PHrxwKFBL8wdSZMX1XxPnAcF4YVU5FMDrV3QNSpnJBePgZ3yMc4epx5SVrEHaJh5GTgNC38GwgdDQ46h88BezoRb9wKNyuMxUwqzxKB6StbWExcshn9UrjE2itxx",
    },
    {
        "key": TEST_ED25519_MONERO_PRIV_KEY,
        "ext": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9oDwUq8hbmYVXq9jRSi64zDnhjwYo5AMM7tJamccfayBLd1QF4",
    },
    {
        "key": TEST_NIST256P1_PRIV_KEY,
        "ext": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAn5ewnjpGej3M4sp2Ko6VjT9cdgsww3GdZwZVYfomqjj5ES3Nq",
    },
    {
        "key": TEST_SECP256K1_PRIV_KEY,
        "ext": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAkzWAg4o7snpEUubcfTkvFE7LgFLqVV97bWwCfT6M27dRW7hQW",
    },
]

# Invalid public keys for testing
TEST_INVALID_PUB_KEYS = [
    {"keys": TEST_VECT_ED25519_PUB_KEY_INVALID, "curve": EllipticCurveTypes.ED25519},
    {"keys": TEST_VECT_ED25519_PUB_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_BLAKE2B},
    {"keys": TEST_VECT_ED25519_PUB_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_KHOLAW},
    {"keys": TEST_VECT_ED25519_PUB_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_MONERO},
    {"keys": TEST_VECT_NIST256P1_PUB_KEY_INVALID, "curve": EllipticCurveTypes.NIST256P1},
    {"keys": TEST_VECT_SECP256K1_PUB_KEY_INVALID, "curve": EllipticCurveTypes.SECP256K1},
    {"keys": TEST_VECT_SR25519_PUB_KEY_INVALID, "curve": EllipticCurveTypes.SR25519},
]

# Invalid private keys for testing
TEST_INVALID_PRIV_KEYS = [
    {"keys": TEST_VECT_ED25519_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.ED25519},
    {"keys": TEST_VECT_ED25519_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_BLAKE2B},
    {"keys": TEST_VECT_ED25519_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_KHOLAW},
    {"keys": TEST_VECT_ED25519_MONERO_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.ED25519_MONERO},
    {"keys": TEST_VECT_NIST256P1_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.NIST256P1},
    {"keys": TEST_VECT_SECP256K1_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.SECP256K1},
    {"keys": TEST_VECT_SR25519_PRIV_KEY_INVALID, "curve": EllipticCurveTypes.SR25519},
]

# BIP32 key data for testing
TEST_BIP32_KEY_DATA = Bip32KeyData(Bip32Depth(0),
                                   Bip32KeyIndex(0),
                                   Bip32ChainCode(),
                                   Bip32FingerPrint())


#
# Tests
#
class Bip32KeyDataTests(unittest.TestCase):
    # Test private key
    def test_priv_key(self):
        for i, test in enumerate(TEST_PRIV_KEYS):
            test_pub = TEST_PUB_KEYS[i]

            # FromBytesOrKeyObject (object)
            self.__test_priv_key_obj(
                Bip32PrivateKey.FromBytesOrKeyObject(test["key"],
                                                     TEST_BIP32_KEY_DATA,
                                                     Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                     test["key"].CurveType()),
                test,
                test_pub
            )
            # FromBytesOrKeyObject (bytes)
            self.__test_priv_key_obj(
                Bip32PrivateKey.FromBytesOrKeyObject(test["key"].Raw().ToBytes(),
                                                     TEST_BIP32_KEY_DATA,
                                                     Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                     test["key"].CurveType()),
                test,
                test_pub
            )
            # FromBytes (bytes)
            self.__test_priv_key_obj(
                Bip32PrivateKey.FromBytes(test["key"].Raw().ToBytes(),
                                          TEST_BIP32_KEY_DATA,
                                          Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                          test["key"].CurveType()),
                test,
                test_pub
            )

    # Test public key
    def test_pub_key(self):
        for test in TEST_PUB_KEYS:
            # FromBytesOrKeyObject (public key object)
            self.__test_pub_key_obj(
                Bip32PublicKey.FromBytesOrKeyObject(test["key"],
                                                    TEST_BIP32_KEY_DATA,
                                                    Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                    test["key"].CurveType()),
                test
            )
            # FromBytesOrKeyObject (compressed)
            self.__test_pub_key_obj(
                Bip32PublicKey.FromBytesOrKeyObject(test["key"].RawCompressed().ToBytes(),
                                                    TEST_BIP32_KEY_DATA,
                                                    Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                    test["key"].CurveType()),
                test
            )
            # FromBytesOrKeyObject (uncompressed)
            self.__test_pub_key_obj(
                Bip32PublicKey.FromBytesOrKeyObject(test["key"].RawUncompressed().ToBytes(),
                                                    TEST_BIP32_KEY_DATA,
                                                    Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                    test["key"].CurveType()),
                test
            )

            # FromBytes (uncompressed)
            self.__test_pub_key_obj(
                Bip32PublicKey.FromBytes(test["key"].RawUncompressed().ToBytes(),
                                         TEST_BIP32_KEY_DATA,
                                         Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                         test["key"].CurveType()),
                test
            )
            # FromBytes (compressed)
            self.__test_pub_key_obj(
                Bip32PublicKey.FromBytes(test["key"].RawCompressed().ToBytes(),
                                         TEST_BIP32_KEY_DATA,
                                         Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                         test["key"].CurveType()),
                test
            )
            # Test point if present
            if "point" in test:
                # FromBytesOrKeyObject (point object)
                self.__test_pub_key_obj(
                    Bip32PublicKey.FromBytesOrKeyObject(test["point"],
                                                        TEST_BIP32_KEY_DATA,
                                                        Bip32Const.MAIN_NET_KEY_NET_VERSIONS,
                                                        test["point"].CurveType()),
                    test
                )
                # FromPoint
                self.__test_pub_key_obj(
                    Bip32PublicKey.FromPoint(test["point"],
                                             TEST_BIP32_KEY_DATA,
                                             Bip32Const.MAIN_NET_KEY_NET_VERSIONS),
                    test
                )

    # Test invalid keys
    def test_invalid_keys(self):
        # Invalid private keys
        for test in TEST_INVALID_PRIV_KEYS:
            for key in test["keys"]:
                self.assertRaises(Bip32KeyError, Bip32PrivateKey.FromBytesOrKeyObject, key, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, test["curve"])
        # Invalid public keys
        for test in TEST_INVALID_PUB_KEYS:
            for key in test["keys"]:
                self.assertRaises(Bip32KeyError, Bip32PublicKey.FromBytesOrKeyObject, key, TEST_BIP32_KEY_DATA, Bip32Const.MAIN_NET_KEY_NET_VERSIONS, test["curve"])

    # Test private key object
    def __test_priv_key_obj(self, priv_key, test_priv, test_pub):
        # Objects
        self.assertTrue(isinstance(priv_key.KeyObject(), type(test_priv["key"])))
        self.assertTrue(isinstance(priv_key.Data(), Bip32KeyData))
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        # Curve
        self.assertEqual(EllipticCurveGetter.FromType(test_priv["key"].CurveType()), priv_key.Curve())
        self.assertEqual(test_priv["key"].CurveType(), priv_key.CurveType())
        # Key data
        self.assertTrue(priv_key.Data() is TEST_BIP32_KEY_DATA)
        # Chain code
        self.assertTrue(priv_key.ChainCode() is TEST_BIP32_KEY_DATA.ChainCode())
        # Key
        self.assertEqual(test_priv["key"].Raw().ToBytes(), priv_key.Raw().ToBytes())
        # Extended key
        self.assertEqual(test_priv["ext"], priv_key.ToExtended())
        # Public key associated to the private one
        self.__test_pub_key_obj(priv_key.PublicKey(), test_pub)

    # Test public key object
    def __test_pub_key_obj(self, pub_key, test):
        # Objects
        self.assertTrue(isinstance(pub_key.KeyObject(), type(test["key"])))
        self.assertTrue(isinstance(pub_key.Data(), Bip32KeyData))
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        # Curve
        self.assertEqual(EllipticCurveGetter.FromType(test["key"].CurveType()), pub_key.Curve())
        self.assertEqual(test["key"].CurveType(), pub_key.CurveType())
        # Key data
        self.assertTrue(pub_key.Data() is TEST_BIP32_KEY_DATA)
        # Chain code
        self.assertTrue(pub_key.ChainCode() is TEST_BIP32_KEY_DATA.ChainCode())
        # Keys
        self.assertEqual(test["key"].RawCompressed().ToBytes(), pub_key.RawCompressed().ToBytes())
        self.assertEqual(test["key"].RawUncompressed().ToBytes(), pub_key.RawUncompressed().ToBytes())
        # Extended key
        self.assertEqual(test["ext"], pub_key.ToExtended())
        # Data
        self.assertEqual(binascii.unhexlify(test["fprint"]), pub_key.FingerPrint().ToBytes())
        self.assertEqual(binascii.unhexlify(test["key_id"]), pub_key.KeyIdentifier())
