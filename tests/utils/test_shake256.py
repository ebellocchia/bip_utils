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

from bip_utils import Shake256


# Test vector for SHAKE256 (64-byte digests, generated with hashlib)
TEST_VECT = [
    {
        "data": b"",
        "digest": b"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    },
    {
        "data": b"abc",
        "digest": b"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
    },
    # Same as before, but with data as string
    {
        "data": "abc",
        "digest": b"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
    },
    {
        "data": bytes(range(256)),
        "digest": b"336c8aa7f2b08bda6bd7402cd2ea89760b7728a8b31802b80524756361165366ff8159f2f4568a2bfa286db6387895629938c2868a6421c37f988455763a75e4",
    },
]


#
# Tests
#
class Shake256Tests(unittest.TestCase):
    # Test quick digest
    def test_quick_digest(self):
        for test in TEST_VECT:
            digest = binascii.unhexlify(test["digest"])
            self.assertEqual(digest, Shake256.QuickDigest(test["data"], len(digest)))
            # A shorter digest is a prefix of the longer one
            self.assertEqual(digest[:16], Shake256.QuickDigest(test["data"], 16))

    # Test incremental read
    def test_read(self):
        for test in TEST_VECT:
            digest = binascii.unhexlify(test["digest"])
            shake = Shake256(test["data"])
            self.assertEqual(digest, shake.Read(1) + shake.Read(20) + shake.Read(len(digest) - 21))

    # Test update
    def test_update(self):
        for test in TEST_VECT:
            digest = binascii.unhexlify(test["digest"])
            shake = Shake256()
            shake.Update(test["data"][:2])
            shake.Update(test["data"][2:])
            self.assertEqual(digest, shake.Read(len(digest)))

    # Test update after read
    def test_update_after_read(self):
        shake = Shake256(b"abc")
        shake.Read(1)
        self.assertRaises(TypeError, shake.Update, b"abc")
