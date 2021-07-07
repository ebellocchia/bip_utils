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
    Bip44BitcoinMainNet, Bip44BitcoinTestNet, Bip44DashMainNet, Bip44DashTestNet,
    Bip44DogecoinMainNet, Bip44DogecoinTestNet, Bip44LitecoinMainNet, Bip44LitecoinTestNet,
    WifDecoder, WifEncoder, Base58ChecksumError,
    Ed25519PrivateKey, Ed25519Blake2bPrivateKey, Nist256p1PrivateKey, Secp256k1PrivateKey, Sr25519PrivateKey
)
from .test_ecc import (
    TEST_ED25519_PRIV_KEY, TEST_NIST256P1_PRIV_KEY, TEST_VECT_SECP256K1_PRIV_KEY_INVALID, TEST_SR25519_PRIV_KEY
)

# Some keys randomly generated from:
# https://gobittest.appspot.com/PrivateKey
TEST_VECT = [
    # Bitcoin
    {
        "key_bytes": b"5e9441950b3918772cc3da1fc6735b7c33f1bbe08a8f1e704be46cb664f7e457",
        "encode": "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK2zNk",
        "compr_pub_key": False,
        "net_addr_ver": Bip44BitcoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"5e9441950b3918772cc3da1fc6735b7c33f1bbe08a8f1e704be46cb664f7e457",
        "encode": "92Ja4SCSjMpfj3ChkaiqhB1E5Q5qTimaTeNYsoSUDMRnNiDZUez",
        "compr_pub_key": False,
        "net_addr_ver": Bip44BitcoinTestNet.WifNetVersion(),
    },
    {
        "key_bytes": b"1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67",
        "encode": "Kx2nc8CerNfcsutaet3rPwVtxQvXuQTYxw1mSsfFHsWExJ9xVpLf",
        "compr_pub_key": True,
        "net_addr_ver": Bip44BitcoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67",
        "encode": "cNPn53CWHSMt3MMr3HrymFzxaeDwZrZF2yAEZJ7knzAFD3GTTi2x",
        "compr_pub_key": True,
        "net_addr_ver": Bip44BitcoinTestNet.WifNetVersion(),
    },
    # Dash
    {
        "key_bytes": b"a215750fac2ad0382e40ad02d11aa1467f5ec844f0a7e995c1b3e979fbdc71d0",
        "encode": "7rnFCh34mBbn3uxT9FwNbS4hfdbn7W75u19Jmn3YoS5mXZjPoaX",
        "compr_pub_key": False,
        "net_addr_ver": Bip44DashMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"a215750fac2ad0382e40ad02d11aa1467f5ec844f0a7e995c1b3e979fbdc71d0",
        "encode": "92pJNokBb5GhmdJ8sYfLyf3oid9us9bjSNd5K27vbNKLoLLfwfP",
        "compr_pub_key": False,
        "net_addr_ver": Bip44DashTestNet.WifNetVersion(),
    },
    {
        "key_bytes": b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
        "encode": "XBvs6XpB5U7xxB6muoJmWzFKssp8PzNvPzfQsGMNeLMLcd3pdCC9",
        "compr_pub_key": True,
        "net_addr_ver": Bip44DashMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
        "encode": "cNDw7BRfCrBn4HZfGT82P5ZNb5qxcdsN6TTyTAUgq5jFUD5xFN65",
        "compr_pub_key": True,
        "net_addr_ver": Bip44DashTestNet.WifNetVersion(),
    },
    # Dogecoin
    {
        "key_bytes": b"21f5e16d57b9b70a1625020b59a85fa9342de9c103af3dd9f7b94393a4ac2f46",
        "encode": "6JPaMAeJjouhb8xPzFzETYCHJAJ9wBoFsCyC1LXFSTcZDmHgy6L",
        "compr_pub_key": False,
        "net_addr_ver": Bip44DogecoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"21f5e16d57b9b70a1625020b59a85fa9342de9c103af3dd9f7b94393a4ac2f46",
        "encode": "95jMzQtxU83VnEBwENWAd9xZJdQktdjwBFr8FmcewrAkBNHta8u",
        "compr_pub_key": False,
        "net_addr_ver": Bip44DogecoinTestNet.WifNetVersion(),
    },
    {
        "key_bytes": b"7c5e3d057ec9d8cd61c8e59873fd3ff478cbe0808c444092986e34cc533fa5d7",
        "encode": "QSnP9ZrYTcs3iu5x2uft3mGsnFMMisgshuhAMxYLaES6cndEdopn",
        "compr_pub_key": True,
        "net_addr_ver": Bip44DogecoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"7c5e3d057ec9d8cd61c8e59873fd3ff478cbe0808c444092986e34cc533fa5d7",
        "encode": "ciuibxmCzNuTbrBhwCS18D8JSK2W1cCDDaPyofJCKwzAzG51dDJk",
        "compr_pub_key": True,
        "net_addr_ver": Bip44DogecoinTestNet.WifNetVersion(),
    },
    # Litecoin
    {
        "key_bytes": b"4baa38b7623a40da63836cd9ee8c51d0b6273e766c88adde156fd5fec6e19008",
        "encode": "6uhLoqNczaCPTj3GmT7qfau4Qrp5qb7riHtYshudPgbiGSx3bVs",
        "compr_pub_key": False,
        "net_addr_ver": Bip44LitecoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"4baa38b7623a40da63836cd9ee8c51d0b6273e766c88adde156fd5fec6e19008",
        "encode": "92AEvSedgNoexQehsyDnknfr73cKnxD2HZMLF9F71y29MZAdg13",
        "compr_pub_key": False,
        "net_addr_ver": Bip44LitecoinTestNet.WifNetVersion(),
    },
    {
        "key_bytes": b"abd83a20f1161f5ddb561b64de3e60d2b6350e3b6bc35968e52edb097c73a2c3",
        "encode": "T8p29oRNZpvaE1QbpQ2Fr3kQcrgfzT9KjvzwapwgsqBdMotY6kQW",
        "compr_pub_key": True,
        "net_addr_ver": Bip44LitecoinMainNet.WifNetVersion(),
    },
    {
        "key_bytes": b"abd83a20f1161f5ddb561b64de3e60d2b6350e3b6bc35968e52edb097c73a2c3",
        "encode": "cTLkAy83bWeEccEzfAtX11i6JELmapE7zmF9qSmeoyfU6fQWAyxC",
        "compr_pub_key": True,
        "net_addr_ver": Bip44LitecoinTestNet.WifNetVersion(),
    },
]

# Tests for WIF encoded strings with invalid checksum
TEST_VECT_CHKSUM_INVALID = [
    "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK3zNk",
    "5HzxC8XHHAtoC5jVeScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
    "5JCu9q9GHLHHFS1FqGtLfoFkztBx712cxk4ta6S1UizxLQS6eFp",
]

# Tests for WIF encoded strings with invalid encoding
TEST_VECT_ENC_STR_INVALID = [
    "5JnLHbJUuOcQNc9UC64SizlLYRw9Y2ecbiJW4f8U8htgYLDJVED",
    "5KL1v3EqNOV4bjMHK3x9bxCd9brVhrDt5TbSk43HUfRij7NtZ9p",
    "5JQZOnApGO9pVQLBQXTk6CHoMrzVGcVRGR9NTZizLCQFm4AKa5t",
]

# Tests for invalid keys for encoding
TEST_VECT_ENC_KEY_INVALID = [
    # Public compressed key
    b"0338994349b3a804c44bbec55c2824443ebb9e475dfdad14f4b1a01a97d42751b3",
    # Public uncompressed key
    b"048ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
]

# Tests for invalid keys for decoding
# These wrong encodings were generated on purpose by slightly modifying the WifEncoder.Encode method
TEST_VECT_DEC_KEY_INVALID = [
    # Valid private key with wrong net version prefix (0x79 instead of 0x80)
    "54fKtD9rQfDYgbQ4XpQQPC5r3j6sTpFqEXxBfdveRtM7kJ4s4nK",
    # Private keys with invalid length
    "ye3sXre57tZGpZheVLSm6AvcfAoaPMJaP8f9veXhvxANZxnVJ",
    "3JSPtAmfbMvMSGNUBU85FBDh3muKXzRT4PCxkivBjALfi1j3DUVhxh",
    # Private key with invalid compressed key suffix (0x02 instead of 0x01)
    "KzPZTFDf8uD8m7FPUx2YYzew6BawEVG4cZoeaoWucQWP22cQYAEt",
]


#
# Tests
#
class WifTests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            self.assertEqual(test["key_bytes"],
                             binascii.hexlify(WifDecoder.Decode(test["encode"], test["net_addr_ver"])))

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["key_bytes"])

            self.assertEqual(test["encode"],
                             WifEncoder.Encode(key_bytes,
                                               test["compr_pub_key"],
                                               test["net_addr_ver"]))
            self.assertEqual(test["encode"],
                             WifEncoder.Encode(Secp256k1PrivateKey.FromBytes(key_bytes),
                                               test["compr_pub_key"],
                                               test["net_addr_ver"]))

    # Test invalid checksum
    def test_invalid_checksum(self):
        for test in TEST_VECT_CHKSUM_INVALID:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(Base58ChecksumError):
                WifDecoder.Decode(test)

    # Test invalid encoding
    def test_invalid_encoding(self):
        for test in TEST_VECT_ENC_STR_INVALID:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(ValueError):
                WifDecoder.Decode(test)

    # Test invalid keys for encoding
    def test_enc_invalid_keys(self):
        self.assertRaises(TypeError, WifEncoder.Encode, Ed25519PrivateKey.FromBytes(binascii.unhexlify(TEST_ED25519_PRIV_KEY)))
        self.assertRaises(TypeError, WifEncoder.Encode, Ed25519Blake2bPrivateKey.FromBytes(binascii.unhexlify(TEST_ED25519_PRIV_KEY)))
        self.assertRaises(TypeError, WifEncoder.Encode, Nist256p1PrivateKey.FromBytes(binascii.unhexlify(TEST_NIST256P1_PRIV_KEY)))
        self.assertRaises(TypeError, WifEncoder.Encode, Sr25519PrivateKey.FromBytes(binascii.unhexlify(TEST_SR25519_PRIV_KEY)))

        for test in TEST_VECT_SECP256K1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, WifEncoder.Encode, binascii.unhexlify(test))

        for test in TEST_VECT_ENC_KEY_INVALID:
            self.assertRaises(ValueError, WifEncoder.Encode, binascii.unhexlify(test))

    # Test invalid keys for decoding
    def test_dec_invalid_keys(self):
        for test in TEST_VECT_DEC_KEY_INVALID:
            self.assertRaises(ValueError, WifDecoder.Decode, test)
