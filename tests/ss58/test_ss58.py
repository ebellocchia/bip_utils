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

from bip_utils import SS58ChecksumError, SS58Decoder, SS58Encoder
from bip_utils.ss58.ss58 import SS58Const


# Test vector
TEST_VECT = [
    {
        "raw": b"facc4de5b7745215ec8255c743f044d2a94ef72b2fb6d8e22c35ffbc3ac8ac9e",
        "ss58_format": 0,
        "encode": "16fqfQjHSWMoMxydLYoYixYcTGvcE3csECC69Lik312jNWS9",
    },
    {
        "raw": b"0ae7387f2bbf2846df7a1fb07b0676f1e4c35787f96b6a618e254afea5434d04",
        "ss58_format": 2,
        "encode": "CpcgbdXbwSbUJF38WTzR2r8CpeF29Jeyqm1EZmJmey7sXVE",
    },
    {
        "raw": b"9494d77c224df8b09e05b91ebe7a2f475c12a4cfd103da6b58679b22fc995fda",
        "ss58_format": 42,
        "encode": "5FRXACEYAEcDiWnScWfuqGkYVrq8wyNysbgMGvjDnKLUKFv5",
    },
    {
        "raw": b"f2b0e94f4d04acb16ecbe3348482b207ba6e60585dd641a8b0f6f28ca99795bc",
        "ss58_format": 63,
        "encode": "7P5mRixqQk1Z1h4U15Z2zMc6vKoprgWs645jehsbti5irbc7",
    },
    {
        "raw": b"735ec2e330426e8643745d5bf6b287bfec4e50eaca556c9f2781b02db5e7a236",
        "ss58_format": 64,
        "encode": "cEYBURAnCdz1eMtzsDW3JAz8dEGrahsjYiHXZCBFsxHK7VJX1",
    },
    {
        "raw": b"735ec2e330426e8643745d5bf6b287bfec4e50eaca556c9f2781b02db5e7a236",
        "ss58_format": 127,
        "encode": "jArK6dHqpF4QE6a9H8B54gNRy6hSBzpYBGjCwp4KrqxoADwNq",
    },
]

# Tests for SS58 decode with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid data length
    {
        "enc": "111111111111111111111111111111117dG",
        "ex": ValueError,
    },
    {
        "enc": "1111111111111111111111111111111111L55",
        "ex": ValueError,
    },
    # Reserved formats
    {
        "enc": "5dXqWhZaFSfX13RQLwvM2TD5Mi6UYYtLqBv9Fd79TJrva3NP",
        "ex": ValueError,
    },
    {
        "enc": "5jKVmh6ydjYFA6psFUoNQMUW1CEmbjWs28UGsJkSvATQrTLc",
        "ex": ValueError,
    },
    # Invalid checksum
    {
        "enc": "111111111111111111111111111111111D1n",
        "ex": SS58ChecksumError,
    },
]


#
# Tests
#
class SS58Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            # Test decoder
            ss58_format, dec = SS58Decoder.Decode(test["encode"])
            self.assertEqual((test["ss58_format"], test["raw"]),
                             (ss58_format, binascii.hexlify(dec)))

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            self.assertEqual(test["encode"], SS58Encoder.Encode(binascii.unhexlify(test["raw"]), test["ss58_format"]))

    #  Test invalid calls to encode
    def test_invalid_encode(self):
        data_len = SS58Const.DATA_BYTE_LEN

        self.assertRaises(ValueError, SS58Encoder.Encode, (data_len - 1) * b"\x00", b"\x00")
        self.assertRaises(ValueError, SS58Encoder.Encode, (data_len + 1) * b"\x00", b"\x00")
        self.assertRaises(ValueError, SS58Encoder.Encode, data_len * b"\x00", SS58Const.FORMAT_MAX_VAL + 1)
        self.assertRaises(ValueError, SS58Encoder.Encode, data_len * b"\x00", -1)
        for reserved_format in SS58Const.RESERVED_FORMATS:
            self.assertRaises(ValueError, SS58Encoder.Encode, data_len * b"\x00", reserved_format)

    #  Test invalid calls to decode
    def test_invalid_decode(self):
        for test in TEST_VECT_DEC_INVALID:
            self.assertRaises(test["ex"], SS58Decoder.Decode, test["enc"])
