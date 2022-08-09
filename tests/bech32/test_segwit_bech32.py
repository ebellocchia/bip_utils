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

from bip_utils import Bech32ChecksumError, SegwitBech32Decoder, SegwitBech32Encoder


# Some random public keys
TEST_VECT = [
    {
        "raw": b"751e76e8199196d454941c45d1b3a323f1433bd6",
        "encode": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    },
    {
        "raw": b"30ea99599334801bf09d753af38ba546800bea8b",
        "encode": "bc1qxr4fjkvnxjqphuyaw5a08za9g6qqh65t8qwgum",
    },
    {
        "raw": b"18abaed50b7c1176308baa094b054383b775f12c",
        "encode": "bc1qrz46a4gt0sghvvyt4gy5kp2rswmhtufv6sdq9v",
    },
    {
        "raw": b"5788df3047dd2c2545eee12784e6212745916bb7",
        "encode": "bc1q27yd7vz8m5kz230wuyncfe3pyazez6ah58yzy0",
    },
    {
        "raw": b"3a3eff6f41ce759a8dd95fc1a2d762077f4f3b64",
        "encode": "bc1q8gl07m6pee6e4rwetlq694mzqal57wmyadd9sn",
    },
    {
        "raw": b"37552063bb0baa42b910712df06b814b928a88f0",
        "encode": "bc1qxa2jqcampw4y9wgswyklq6upfwfg4z8s5m4v3v",
    },
    {
        "raw": b"f9ce94eab4ed454dd0077e3dc24bdfb8d5df4008",
        "encode": "bc1ql88ff645a4z5m5q80c7uyj7lhr2a7sqgtss7ek",
    },
    {
        "raw": b"29595a3c78760fe90fe883b922f353b67441d28d",
        "encode": "tb1q99v450rcwc87jrlgswuj9u6nke6yr55drpxuj0",
    },
    {
        "raw": b"b819a85f25b116c2f7e64416a55b8d49b744d209",
        "encode": "tb1qhqv6she9kytv9alxgst22kudfxm5f5sf2lgpc6",
    },
    {
        "raw": b"904c82e2c1a8508ba784e4e53e195b5047682e87",
        "encode": "tb1qjpxg9ckp4pgghfuyunjnux2m2prkst580chf9n",
    },
]

# Tests for Segwit encoded addresses that are not valid from BIP-0173 page, plus a couple for better code coverage
TEST_VECT_ADDR_INVALID = [
    #
    # From BIP-0173 page (removed the ones that collide with BIP-0350)
    #

    # Invalid human-readable part
    {
        "addr": "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "hrp": "tb",
        "ex": ValueError,
    },
    # Invalid checksum
    {
        "addr": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "hrp": "bc",
        "ex": Bech32ChecksumError,
    },
    # Non-zero padding in 8-to-5 conversion
    {
        "addr": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "hrp": "tb",
        "ex": ValueError,
    },

    #
    # From BIP-0350 page
    #

    # Invalid human-readable part
    {
        "addr": "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "hrp": "tb",
        "ex": ValueError,
    },
    # Invalid checksum (Bech32 instead of Bech32m)
    {
        "addr": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "hrp": "bc",
        "ex": Bech32ChecksumError,
    },
    # Invalid checksum (Bech32 instead of Bech32m)
    {
        "addr": "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "hrp": "tb",
        "ex": Bech32ChecksumError,
    },
    # Invalid checksum (Bech32 instead of Bech32m)
    {
        "addr": "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "hrp": "bc",
        "ex": Bech32ChecksumError,
    },
    # Invalid checksum (Bech32m instead of Bech32)
    {
        "addr": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "hrp": "bc",
        "ex": Bech32ChecksumError,
    },
    # Invalid checksum (Bech32m instead of Bech32)
    {
        "addr": "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "hrp": "tb",
        "ex": Bech32ChecksumError,
    },
    # Invalid character in checksum
    {
        "addr": "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Invalid witness version
    {
        "addr": "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Invalid program length (1 byte)
    {
        "addr": "bc1pw5dgrnzv",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Invalid program length (41 bytes)
    {
        "addr": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Invalid program length for witness version 0
    {
        "addr": "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Mixed case
    {
        "addr": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "hrp": "tb",
        "ex": ValueError,
    },
    # Zero padding of more than 4 bits
    {
        "addr": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "hrp": "bc",
        "ex": ValueError,
    },
    # Non-zero padding in 8-to-5 conversion
    {
        "addr": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "hrp": "tb",
        "ex": ValueError,
    },
    # Empty data section
    {
        "addr": "bc1gmk9yu",
        "hrp": "bc",
        "ex": ValueError,
    },

    #
    # Added for improving code coverage
    #

    # Invalid HRP characters
    {
        "addr": "t 1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "hrp": "tb",
        "ex": ValueError,
    },
    # No separator
    {
        "addr": "tbqrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "hrp": "tb",
        "ex": ValueError,
    },
    # Empty HRP
    {
        "addr": "qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "hrp": "tb",
        "ex": ValueError,
    },
]


#
# Tests
#
class SegwitBech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            # Test decoder
            hrp = test["encode"][:test["encode"].find("1")]
            wit_ver, wit_prog = SegwitBech32Decoder.Decode(hrp, test["encode"])

            self.assertEqual(wit_ver, 0)
            self.assertEqual(binascii.hexlify(wit_prog), test["raw"])

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            hrp = test["encode"][:test["encode"].find("1")]
            enc = SegwitBech32Encoder.Encode(hrp, 0, binascii.unhexlify(test["raw"]))
            self.assertEqual(test["encode"], enc)

    # Test invalid address
    def test_invalid_addr(self):
        for test in TEST_VECT_ADDR_INVALID:
            self.assertRaises(test["ex"], SegwitBech32Decoder.Decode, test["hrp"], test["addr"])
