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

from bip_utils import BchBech32Decoder, BchBech32Encoder, CoinsConf


# Some random public keys
TEST_VECT = [
    {
        "raw": b"751e76e8199196d454941c45d1b3a323f1433bd6",
        "encode": "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h",
    },
    {
        "raw": b"30ea99599334801bf09d753af38ba546800bea8b",
        "encode": "bitcoincash:qqcw4x2ejv6gqxlsn46n4uut54rgqzl23v4y77ks69",
    },
    {
        "raw": b"18abaed50b7c1176308baa094b054383b775f12c",
        "encode": "bitcoincash:qqv2htk4pd7pza3s3w4qjjc9gwpmwa039s9cgntx7v",
    },
    {
        "raw": b"29595a3c78760fe90fe883b922f353b67441d28d",
        "encode": "bchtest:qq54jk3u0pmql6g0azpmjghn2wm8gswj35af22xyv3",
    },
    {
        "raw": b"b819a85f25b116c2f7e64416a55b8d49b744d209",
        "encode": "bchtest:qzupn2zlykc3dshhuezpdf2m34ymw3xjpycg0fwyaq",
    },
    {
        "raw": b"904c82e2c1a8508ba784e4e53e195b5047682e87",
        "encode": "bchtest:qzgyeqhzcx59pza8snjw20setdgyw6pwsulf9dv498",
    },
]

# Tests for BCH encoded addresses
# Few tests because most cases are already covered by Segwit tests
TEST_VECT_ADDR_INVALID = [
    # Invalid human-readable part
    {
        "addr": "bitciincash:qq54jk3u0pmql6g0azpmjghn2wm8gswj35853zv6sr",
        "hrp": "bitcoincash",
    },
]


#
# Tests
#
class BchBech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            # Test decoder
            hrp = test["encode"][:test["encode"].find(":")]
            net_ver, dec = BchBech32Decoder.Decode(hrp, test["encode"])

            self.assertEqual(net_ver, CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"))
            self.assertEqual(binascii.hexlify(dec), test["raw"])

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            hrp = test["encode"][:test["encode"].find(":")]
            enc = BchBech32Encoder.Encode(hrp,
                                          CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"),
                                          binascii.unhexlify(test["raw"]))
            self.assertEqual(test["encode"], enc)

    # Test invalid address
    def test_invalid_addr(self):
        for test in TEST_VECT_ADDR_INVALID:
            self.assertRaises(ValueError, BchBech32Decoder.Decode, test["hrp"], test["addr"])
