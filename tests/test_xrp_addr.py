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
from bip_utils import XrpAddr, Ed25519PublicKey, Secp256k1PublicKey

# Some random public keys (verified with https://iancoleman.io/bip39/)
TEST_VECT = [
    {
        "pub_key": b"03db0da69187edd94aba300f1b2e7a09f407a8301d6fff54322a6ee4dde9842681",
        "address": "rwypvr27pYpzYQyDrFQBjDUhRDkHiecTHo",
    },
    {
        "pub_key": b"03333f37539bf526280cea9dda98758de4feb15910218e3e0a99ac17d1f5fac406",
        "address": "rLynFggnosDyDmoLzcgX6siu6X4yUBb36a",
    },
    {
        "pub_key": b"02553f6711f6ed3e1204dff91d9bf259ea01a2577dcc05383ce47f2cc5a98946bc",
        "address": "rJ6twS2cq28qMybswjQHb6BZK7kuwSFfZo",
    },
    {
        "pub_key": b"03530f281debbda165f54090b930c4467842231c3bd2e547d953444c7409ad4c20",
        "address": "rhs1osifPgg35Ff8pRk23vRtn6rhivVuTq",
    },
    {
        "pub_key": b"021cf750242895325d49efa12859369f7a45e9c3f5639172e4f2f5df4ae23301cf",
        "address": "rsfsErX3u9GRrMH1Nr6Qa4TAyWa53bx48D",
    },
]

# Tests for invalid keys
TEST_VECT_KEY_INVALID = [
    # Private key
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
    # Compressed public key with valid length but wrong version
    b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
    # Compressed public key with invalid length
    b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
    # Uncompressed public key with valid length but wrong version
    b"058ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
    # Uncompressed public key with invalid length
    b"04fd87569e9af6015d9d938c67c68fcdf5440d3c235eccbc1195a1924bba90e5e1954cb6d841054791ac227a8c11f79f77d24a20b238402c5424c8e436bb49",
]


#
# Tests
#
class XrpAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], XrpAddr.ToAddress(key_bytes))
            self.assertEqual(test["address"], XrpAddr.ToAddress(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, XrpAddr.ToAddress, Ed25519PublicKey(b"000102030405060708090a0b0c0d0e0f"))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, XrpAddr.ToAddress, binascii.unhexlify(test))
