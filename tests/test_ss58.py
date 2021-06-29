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
from bip_utils import SS58Decoder, SS58Encoder, SS58ChecksumError
from bip_utils.ss58.ss58 import SS58Const

# Test vector
TEST_VECT = [
    {
        "raw": b"facc4de5b7745215ec8255c743f044d2a94ef72b2fb6d8e22c35ffbc3ac8ac9e",
        "version": b"\x00",
        "encode": "16fqfQjHSWMoMxydLYoYixYcTGvcE3csECC69Lik312jNWS9",
    },
    {
        "raw": b"0ae7387f2bbf2846df7a1fb07b0676f1e4c35787f96b6a618e254afea5434d04",
        "version": b"\x00",
        "encode": "1FJAcYiqMh9ABS7KShwfEKGurMeun3cbxek1CUhqwn9JxKk",
    },
    {
        "raw": b"9494d77c224df8b09e05b91ebe7a2f475c12a4cfd103da6b58679b22fc995fda",
        "version": b"\x00",
        "encode": "14MpJXVc21shA3nxa9iuyRahMUpneGw7x6QqSDiaLQMzVm7a",
    },
    {
        "raw": b"f2b0e94f4d04acb16ecbe3348482b207ba6e60585dd641a8b0f6f28ca99795bc",
        "version": b"\x00",
        "encode": "16VD9DrSCQumAzaEwY8YCarLCkoJQ8r5CoBTteMdiqd18CbK",
    },
    {
        "raw": b"735ec2e330426e8643745d5bf6b287bfec4e50eaca556c9f2781b02db5e7a236",
        "version": b"\x00",
        "encode": "13cGf6D7dWC9hjpMqmNrohXw4tCSgWDqZ5rbE47dLFcqk7ZL",
    },
]

# Tests for ss58 decode with invalid strings
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
            version, dec = SS58Decoder.Decode(test["encode"])
            self.assertEqual((test["version"], test["raw"]),
                             (version, binascii.hexlify(dec)))

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            # Test encoder
            self.assertEqual(test["encode"], SS58Encoder.Encode(binascii.unhexlify(test["raw"]), test["version"]))

    #  Test invalid calls to encode
    def test_invalid_encode(self):
        data_len = SS58Const.DATA_BYTE_LEN
        ver_len = SS58Const.VERSION_BYTE_LEN

        self.assertRaises(ValueError, SS58Encoder.Encode, (data_len - 1) * b"\x00", b"\x00")
        self.assertRaises(ValueError, SS58Encoder.Encode, (data_len + 1) * b"\x00", b"\x00")
        self.assertRaises(ValueError, SS58Encoder.Encode, data_len * b"\x00", (ver_len + 1) * b"\x00")

    #  Test invalid calls to decode
    def test_invalid_decode(self):
        for test in TEST_VECT_DEC_INVALID:
            self.assertRaises(test["ex"], SS58Decoder.Decode, test["enc"])
