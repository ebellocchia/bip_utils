# Copyright (c) 2026 Emanuele Bellocchia
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

from bip_utils import XModemCrc


# Test vector for XMODEM-CRC
TEST_VECT_XMODEM = [
    {
        "data": b"",
        "digest": b"0000",
    },
    # Standard check value
    {
        "data": b"123456789",
        "digest": b"31c3",
    },
    # Same as before, but with data as string
    {
        "data": "123456789",
        "digest": b"31c3",
    },
    # Digest whose most significant byte is zero
    {
        "data": b"cr",
        "digest": b"00ac",
    },
    {
        "data": b"The quick brown fox jumps over the lazy dog",
        "digest": b"f0c8",
    },
    {
        "data": bytes(range(256)),
        "digest": b"7e55",
    },
]


#
# Tests
#
class XModemCrcTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT_XMODEM:
            self.assertEqual(binascii.unhexlify(test["digest"]), XModemCrc.QuickDigest(test["data"]))

    # Test digest size
    def test_digest_size(self):
        self.assertEqual(2, XModemCrc.DigestSize())
