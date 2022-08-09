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
    SubstrateScaleBytesEncoder, SubstrateScaleCUintEncoder, SubstrateScaleU8Encoder, SubstrateScaleU16Encoder,
    SubstrateScaleU32Encoder, SubstrateScaleU64Encoder, SubstrateScaleU128Encoder, SubstrateScaleU256Encoder
)


# Test vector
TEST_VECT = [
    # Unsigned integers
    {
        "scale_enc": SubstrateScaleU8Encoder,
        "value": 12,
        "enc_value": b"0c",
    },
    {
        "scale_enc": SubstrateScaleU16Encoder,
        "value": 18426,
        "enc_value": b"fa47",
    },
    {
        "scale_enc": SubstrateScaleU32Encoder,
        "value": 1706095648,
        "enc_value": b"20f4b065",
    },
    {
        "scale_enc": SubstrateScaleU64Encoder,
        "value": 2579765632504954883,
        "enc_value": b"030038b12c2bcd23",
    },
    {
        "scale_enc": SubstrateScaleU64Encoder,
        "value": "2579765632504954883",
        "enc_value": b"030038b12c2bcd23",
    },
    {
        "scale_enc": SubstrateScaleU128Encoder,
        "value": 1981057649835179426526325300541830,
        "enc_value": b"8639b01a20016476244b8076ac610000",
    },
    {
        "scale_enc": SubstrateScaleU256Encoder,
        "value": 4512471174635598247890384632897562349411987594382343298700199879854632446,
        "enc_value": b"fead49273e86747ef831ed3aba591de566f0989853ffccb38852bddbd08d0200",
    },
    # Compact unsigned integers
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 48,
        "enc_value": b"c0",
    },
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 13429,
        "enc_value": b"d5d1",
    },
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 1013741822,
        "enc_value": b"fae3b1f1",
    },
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 2579765632504954883,
        "enc_value": b"13030038b12c2bcd23",
    },
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 1981057649835179426526325300541830,
        "enc_value": b"2b8639b01a20016476244b8076ac61",
    },
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 4512471174635598247890384632897562349411987594382343298700199879854632446,
        "enc_value": b"6ffead49273e86747ef831ed3aba591de566f0989853ffccb38852bddbd08d02",
    },
    # Bytes
    {
        "scale_enc": SubstrateScaleBytesEncoder,
        "value": b"58709af4e16b",
        "enc_value": b"1858709af4e16b",
    },
    # Strings
    {
        "scale_enc": SubstrateScaleBytesEncoder,
        "value": "Test string",
        "enc_value": b"2c5465737420737472696e67",
    },
]

# Test vector for invalid values
TEST_VECT_VALUE_INVALID = [
    # Unsigned integers
    {
        "scale_enc": SubstrateScaleU8Encoder,
        "value": 2**8,
    },
    {
        "scale_enc": SubstrateScaleU16Encoder,
        "value": 2**16,
    },
    {
        "scale_enc": SubstrateScaleU32Encoder,
        "value": 2**32,
    },
    {
        "scale_enc": SubstrateScaleU64Encoder,
        "value": 2**64,
    },
    {
        "scale_enc": SubstrateScaleU128Encoder,
        "value": 2**128,
    },
    {
        "scale_enc": SubstrateScaleU256Encoder,
        "value": 2**256,
    },
    # Compact unsigned integers
    {
        "scale_enc": SubstrateScaleCUintEncoder,
        "value": 2**536,
    },
]


#
# Tests
#
class SubstrateTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            scale_enc = test["scale_enc"]
            value = test["value"] if not isinstance(test["value"], bytes) else binascii.unhexlify(test["value"])
            self.assertEqual(test["enc_value"], binascii.hexlify(scale_enc.Encode(value)))

    # Test invalid values
    def test_invalid_value(self):
        for test in TEST_VECT_VALUE_INVALID:
            scale_enc = test["scale_enc"]
            self.assertRaises(ValueError, scale_enc.Encode, test["value"])
