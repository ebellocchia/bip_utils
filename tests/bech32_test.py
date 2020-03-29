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
from bip_utils import Bech32Decoder, Bech32Encoder


# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "raw"    : b"751e76e8199196d454941c45d1b3a323f1433bd6",
            "encode" :  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        },
        {
            "raw"    : b"30ea99599334801bf09d753af38ba546800bea8b",
            "encode" :  "bc1qxr4fjkvnxjqphuyaw5a08za9g6qqh65t8qwgum",
        },
        {
            "raw"    : b"18abaed50b7c1176308baa094b054383b775f12c",
            "encode" :  "bc1qrz46a4gt0sghvvyt4gy5kp2rswmhtufv6sdq9v",
        },
        {
            "raw"    : b"5788df3047dd2c2545eee12784e6212745916bb7",
            "encode" :  "bc1q27yd7vz8m5kz230wuyncfe3pyazez6ah58yzy0",
        },
        {
            "raw"    : b"3a3eff6f41ce759a8dd95fc1a2d762077f4f3b64",
            "encode" :  "bc1q8gl07m6pee6e4rwetlq694mzqal57wmyadd9sn",
        },
        {
            "raw"    : b"37552063bb0baa42b910712df06b814b928a88f0",
            "encode" :  "bc1qxa2jqcampw4y9wgswyklq6upfwfg4z8s5m4v3v",
        },
        {
            "raw"    : b"f9ce94eab4ed454dd0077e3dc24bdfb8d5df4008",
            "encode" :  "bc1ql88ff645a4z5m5q80c7uyj7lhr2a7sqgtss7ek",
        },
        {
            "raw"    : b"29595a3c78760fe90fe883b922f353b67441d28d",
            "encode" :  "tb1q99v450rcwc87jrlgswuj9u6nke6yr55drpxuj0",
        },
        {
            "raw"    : b"b819a85f25b116c2f7e64416a55b8d49b744d209",
            "encode" :  "tb1qhqv6she9kytv9alxgst22kudfxm5f5sf2lgpc6",
        },
        {
            "raw"    : b"904c82e2c1a8508ba784e4e53e195b5047682e87",
            "encode" :  "tb1qjpxg9ckp4pgghfuyunjnux2m2prkst580chf9n",
        },
    ]

# Bech32 encoded addresses that are not valid from BIP-0173 page
TEST_VECTOR_INVALID_ADDR = \
    [
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
        "bc1rw5uspcuh",
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "bc1gmk9yu",
    ]


#
# Tests
#
class Bech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECTOR:
            # Test decoder
            hrp = test["encode"][:2]
            dec = Bech32Decoder.DecodeAddr(hrp, test["encode"])

            self.assertEqual(binascii.hexlify(dec[1]), test["raw"])
            self.assertEqual(dec[0], 0)

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECTOR:
            # Test encoder
            hrp = test["encode"][:2]
            enc = Bech32Encoder.EncodeAddr(hrp, 0, binascii.unhexlify(test["raw"]))
            self.assertEqual(test["encode"], enc)

    # Test invalid
    def test_invalid_addr(self):
        for test in TEST_VECTOR_INVALID_ADDR:
            self.assertRaises(RuntimeError,  Bech32Decoder.DecodeAddr, "bc", test)
            self.assertRaises(RuntimeError,  Bech32Decoder.DecodeAddr, "tb", test)


# Run test if executed
if __name__ == "__main__":
    unittest.main()
