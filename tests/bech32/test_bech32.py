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

from bip_utils import Bech32Decoder, Bech32Encoder


# Some random public keys
TEST_VECT = [
    {
        "raw": b"751e76e8199196d454941c45d1b3a323f1433bd6",
        "encode": "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c",
    },
    {
        "raw": b"30ea99599334801bf09d753af38ba546800bea8b",
        "encode": "cosmos1xr4fjkvnxjqphuyaw5a08za9g6qqh65t36srck",
    },
    {
        "raw": b"18abaed50b7c1176308baa094b054383b775f12c",
        "encode": "band1rz46a4gt0sghvvyt4gy5kp2rswmhtufv49nfef",
    },
    {
        "raw": b"29595a3c78760fe90fe883b922f353b67441d28d",
        "encode": "band199v450rcwc87jrlgswuj9u6nke6yr55dxjrx4e",
    },
]

# Tests for  encoded addresses
# Few tests because most cases are already covered by Segwit tests
TEST_VECT_ADDR_INVALID = [
    # Invalid human-readable part
    {
        "addr": "cosmis1w508d6qejxtdg4y5r3zarvary0c5xw7khxen85",
        "hrp": "cosmos",
    },
]


#
# Tests
#
class Bech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            # Test decoder
            hrp = test["encode"][:test["encode"].find("1")]
            dec = Bech32Decoder.Decode(hrp, test["encode"])
            self.assertEqual(binascii.hexlify(dec), test["raw"])

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            hrp = test["encode"][:test["encode"].find("1")]
            enc = Bech32Encoder.Encode(hrp, binascii.unhexlify(test["raw"]))
            self.assertEqual(test["encode"], enc)

    # Test invalid address
    def test_invalid_addr(self):
        for test in TEST_VECT_ADDR_INVALID:
            self.assertRaises(ValueError, Bech32Decoder.Decode, test["hrp"], test["addr"])
