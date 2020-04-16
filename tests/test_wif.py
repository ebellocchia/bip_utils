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
import unittest
from bip_utils import BitcoinConf, LitecoinConf, DogecoinConf, DashConf, WifDecoder, WifEncoder, Base58ChecksumError


# Some keys randomly generated from:
# https://gobittest.appspot.com/PrivateKey
TEST_MAIN = \
    [
        # Private keys
        {
            "key_bytes"    : b"5e9441950b3918772cc3da1fc6735b7c33f1bbe08a8f1e704be46cb664f7e457",
            "encode"       :  "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK2zNk",
            "net_addr_ver" :  BitcoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67",
            "encode"       :  "5HzxC8XHHAtoC5jVvScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
            "net_addr_ver" :  BitcoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"4baa38b7623a40da63836cd9ee8c51d0b6273e766c88adde156fd5fec6e19008",
            "encode"       :  "6uhLoqNczaCPTj3GmT7qfau4Qrp5qb7riHtYshudPgbiGSx3bVs",
            "net_addr_ver" :  LitecoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"abd83a20f1161f5ddb561b64de3e60d2b6350e3b6bc35968e52edb097c73a2c3",
            "encode"       :  "6vRhbAcRpmPZT4GKJzKs33tXGpxfHeBwzkxGYE8QY13QePS9TdM",
            "net_addr_ver" :  LitecoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"21f5e16d57b9b70a1625020b59a85fa9342de9c103af3dd9f7b94393a4ac2f46",
            "encode"       :  "6JPaMAeJjouhb8xPzFzETYCHJAJ9wBoFsCyC1LXFSTcZDmHgy6L",
            "net_addr_ver" :  DogecoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"7c5e3d057ec9d8cd61c8e59873fd3ff478cbe0808c444092986e34cc533fa5d7",
            "encode"       :  "6K5Ph1CE23gtNGsxyAfiUMuXzNq7WRdDr9KANWoXGETz1SNNZYf",
            "net_addr_ver" :  DogecoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"a215750fac2ad0382e40ad02d11aa1467f5ec844f0a7e995c1b3e979fbdc71d0",
            "encode"       :  "7rnFCh34mBbn3uxT9FwNbS4hfdbn7W75u19Jmn3YoS5mXZjPoaX",
            "net_addr_ver" :  DashConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
            "encode"       :  "7qhJEwZSPmCzzMsFFgVVfWjfiS79UQsjTWNqud6yZUVdASqwap5",
            "net_addr_ver" :  DashConf.WIF_NET_VER.Main(),
        },
        # Public compressed key
        {
            "key_bytes"    : b"0338994349b3a804c44bbec55c2824443ebb9e475dfdad14f4b1a01a97d42751b3",
            "encode"       :  "2SanjgwXS8KTJb1Pv7YGCMCfRSWU8Qw4F1fG1PmAxrgZ9cCZosxosN",
            "net_addr_ver" :  BitcoinConf.WIF_NET_VER.Main(),
        },
        {
            "key_bytes"    : b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
            "encode"       :  "2Sahb5hCJow8gvz5fq5Wh1dun8GUvTpcfr3Px4jDf1HhYD7D7Z8JCT",
            "net_addr_ver" :  BitcoinConf.WIF_NET_VER.Main(),
        },
        # Public uncompressed key
        {
            "key_bytes"    : b"aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e9370164133294e5fd1679672fe7866c307daf97281a28f66dca7cbb52919824f",
            "encode"       :  "2HJMDEE3pAbtM7ij1NDWgUXnoNBhM5WC8enF3X5BbFhtfCMy1ULFm1bpxKA4CzHmgPnMY2UNSsp5v5FeEmsySYcruiQzLHC",
            "net_addr_ver" :  BitcoinConf.WIF_NET_VER.Main(),
        },
    ]

# Some WIF encoded strings with invalid checksum
TEST_CHKSUM_INVALID = \
    [
        "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK3zNk",
        "5HzxC8XHHAtoC5jVeScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
        "5JCu9q9GHLHHFS1FqGtLfoFkztBx712cxk4ta6S1UizxLQS6eFp",
    ]

# Some WIF encoded strings with invalid encoding
TEST_ENC_STR_INVALID = \
    [
        "5JnLHbJUuOcQNc9UC64SizlLYRw9Y2ecbiJW4f8U8htgYLDJVED",
        "5KL1v3EqNOV4bjMHK3x9bxCd9brVhrDt5TbSk43HUfRij7NtZ9p",
        "5JQZOnApGO9pVQLBQXTk6CHoMrzVGcVRGR9NTZizLCQFm4AKa5t",
    ]

# Some invalid keys for encoding
TEST_ENC_KEY_INVALID = \
    [
        # Private key with invalid length
        b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e",
        # Compressed public key with valid length but wrong version (0x01)
        b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
        # Compressed public key with invalid length
        b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
        # Uncompressed public key with invalid length
        b"aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e9370164133294e5fd1679672fe7866c307daf97281a28f66dca7cbb5291982"
    ]

# Some invalid keys for decoding
# These wrong encodings were generated on purpose by slightly modifying the WifEncoder.Encode method
TEST_DEC_KEY_INVALID = \
    [
        # Valid private key with wrong net version prefix (0x79 instead of 0x80)
        "54fKtD9rQfDYgbQ4XpQQPC5r3j6sTpFqEXxBfdveRtM7kJ4s4nK",
        # Private key with invalid length
        "ye3sXre57tZGpZheVLSm6AvcfAoaPMJaP8f9veXhvxANZxnVJ",
        # Compressed public key with valid length but wrong version (0x01 instead of 0x02 or 0x03)
        "2SaZ1T82wukymo1Zf4XSJ7qjge23iozCQ7sxKwAmJuoDnVpt1DKCHv",
        # Compressed public key with invalid length
        "7Muk9RiQuc9vwFGwcPCv3bouxB5LEyPASTTaJ3TLrkGhvkSQU1a4RMw",
        # Compressed public key with invalid added suffix (0x02 instead of 0x01)
        "2Sahb5hCJow8gvz5fq5Wh1dun8GUvTpcfr3Px4jDf1HhYD7DHXiKYy",
        # Uncompressed public key with invalid length
        "HsjZzgDFeJDh69NCV9YPatTWuY7zusKt5bwgvJu6U3FrA4MB87b6nQAXogEuvKvXf2Y8Dw1T5n4fjwiFqhHM1wHv2iyvG"
    ]


#
# Tests
#
class WifTests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_MAIN:
            # Test decoder
            self.assertEqual(test["key_bytes"], binascii.hexlify(WifDecoder.Decode(test["encode"], test["net_addr_ver"])))

    # Test encoder
    def test_encoder(self):
        for test in TEST_MAIN:
            # Test encoder
            self.assertEqual(test["encode"], WifEncoder.Encode(binascii.unhexlify(test["key_bytes"]), test["net_addr_ver"]))

    # Test invalid checksum
    def test_invalid_checksum(self):
        for test in TEST_CHKSUM_INVALID:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(Base58ChecksumError):
                WifDecoder.Decode(test)

    # Test invalid encoding
    def test_invalid_encoding(self):
        for test in TEST_ENC_STR_INVALID:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(ValueError):
                WifDecoder.Decode(test)

    # Test invalid keys for encoding
    def test_enc_invalid_keys(self):
        for test in TEST_ENC_KEY_INVALID:
            self.assertRaises(ValueError, WifEncoder.Encode, binascii.unhexlify(test))

    # Test invalid keys for decoding
    def test_dec_invalid_keys(self):
        for test in TEST_DEC_KEY_INVALID:
            self.assertRaises(ValueError, WifDecoder.Decode, test)
