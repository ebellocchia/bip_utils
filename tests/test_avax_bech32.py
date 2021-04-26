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
from bip_utils import (
    AvaxChainTypes, AvaxBech32Decoder, AvaxBech32Encoder, Bech32FormatError
)

# Some keys randomly taken
TEST_VECT = [
        {
            "raw": b"820775595b4c5b08cf2621349ff2bf41c52b527a",
            "chain": AvaxChainTypes.AVAX_X_CHAIN,
            "encode": "X-avax1sgrh2k2mf3ds3nexyy6flu4lg8zjk5n6p20rq5",
        },
        {
            "raw": b"3f13ce4d02e1f76f66f30768869f0ca7f913b078",
            "chain": AvaxChainTypes.AVAX_X_CHAIN,
            "encode": "X-avax18ufuungzu8mk7ehnqa5gd8cv5lu38vrcjejss8",
        },
        {
            "raw": b"e0a2c1fe6f02b86280ee19469d2608344311372d",
            "chain": AvaxChainTypes.AVAX_P_CHAIN,
            "encode": "P-avax1uz3vrln0q2ux9q8wr9rf6fsgx3p3zded7ss4gc",
        },
        {
            "raw": b"53431a2de95ec852624665cc8baed892f48906c0",
            "chain": AvaxChainTypes.AVAX_P_CHAIN,
            "encode": "P-avax12dp35t0ftmy9ycjxvhxghtkcjt6gjpkqn8gft8",
        },
    ]

# Tests for Avax encoded addresses
# Few tests because most cases are already covered by Atom tests
TEST_VECT_ADDR_INVALID = [
        # Invalid prefix
        "E-avax123ghjvxx49h87g0vk26c97ca8x3v44g5n9mzha",
    ]


#
# Tests
#
class AvaxBech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            # Test decoder
            chain_type, dec = AvaxBech32Decoder.Decode(test["encode"])
            self.assertEqual(binascii.hexlify(dec), test["raw"])
            self.assertEqual(chain_type, test["chain"])

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            enc = AvaxBech32Encoder.Encode(binascii.unhexlify(test["raw"]), test["chain"])
            self.assertEqual(test["encode"], enc)

    # Test invalid address
    def test_invalid_addr(self):
        for test in TEST_VECT_ADDR_INVALID:
            self.assertRaises(Bech32FormatError, AvaxBech32Decoder.Decode, test)
