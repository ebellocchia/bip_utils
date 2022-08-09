# Copyright (c) 2022 Emanuele Bellocchia
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

from bip_utils.utils.misc import CborIndefiniteLenArrayDecoder, CborIndefiniteLenArrayEncoder


# Test vector
TEST_VECT = [
    {
        "elems": [23, 2**8 - 1, 2**16 - 1, 2**32 - 1, 2**64 - 1],
        "encode": b"9f1718ff19ffff1affffffff1bffffffffffffffffff",
    },
    {
        "elems": [0, 24, 2**8, 2**16, 2**32],
        "encode": b"9f0018181901001a000100001b0000000100000000ff",
    },
]

# Test vector for invalid encoding
TEST_VECT_INVALID_ENC = [
    b"0011",
    b"9e1818190100ff",
    b"9f1818190100fe",
    b"9f18181901ff",
]


#
# Tests
#
class CborIndefiniteLenArrayTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            self.assertEqual(binascii.unhexlify(test["encode"]), CborIndefiniteLenArrayEncoder.Encode(test["elems"]))
            self.assertEqual(test["elems"], CborIndefiniteLenArrayDecoder.Decode(binascii.unhexlify(test["encode"])))

    # Test invalid parameters
    def test_invalid_params(self):
        for test in TEST_VECT_INVALID_ENC:
            self.assertRaises(ValueError, CborIndefiniteLenArrayDecoder.Decode, binascii.unhexlify(test))
