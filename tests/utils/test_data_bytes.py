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
from bip_utils import DataBytes

# Test vector
TEST_VECT = [
    {
        "bytes": b"1234",
        "hex": "1234",
        "int_big": 4660,
        "int_little": 13330,
    },
    {
        "bytes": b"001234",
        "hex": "001234",
        "int_big": 4660,
        "int_little": 3412480,
    },
    {
        "bytes": b"000102030405060708090a0b0c0d0e0f",
        "hex": "000102030405060708090a0b0c0d0e0f",
        "int_big": 5233100606242806050955395731361295,
        "int_little": 20011376718272490338853433276725592320,
    },
]


#
# Tests
#
class DataBytesTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            test_bytes = binascii.unhexlify(test["bytes"])
            data_bytes = DataBytes(test_bytes)

            # ByteLength
            self.assertEqual(len(test_bytes), data_bytes.Length())
            self.assertEqual(len(test_bytes), data_bytes.Size())
            # Bytes
            self.assertEqual(test_bytes, data_bytes.ToBytes())
            self.assertEqual(test_bytes, bytes(data_bytes))
            self.assertEqual(test_bytes, data_bytes)
            # String
            self.assertEqual(test["hex"], data_bytes.ToHex())
            self.assertEqual(test["hex"], repr(data_bytes))
            self.assertEqual(test["hex"], str(data_bytes))
            self.assertEqual(test["hex"], data_bytes)
            # Integer
            self.assertEqual(test["int_big"], data_bytes.ToInt())
            self.assertEqual(test["int_big"], int(data_bytes.ToInt()))
            self.assertEqual(test["int_big"], data_bytes)
            self.assertEqual(test["int_little"], data_bytes.ToInt("little"))
            # [] operator
            for i in range(len(test_bytes)):
                self.assertEqual(test_bytes[i], data_bytes[i])
            # Equality operator
            self.assertEqual(DataBytes(test_bytes), data_bytes)

    # Test invalid parameters
    def test_invalid_parameters(self):
        self.assertRaises(TypeError, DataBytes(b"").__eq__, [])
