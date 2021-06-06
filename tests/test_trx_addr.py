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
from bip_utils import TrxAddr, Ed25519PublicKey, Secp256k1PublicKey

# Some keys randomly taken (verified with TronLink wallet)
TEST_VECT = [
    {
        "pub_key": b"033d77bf3f63edd7aad3163c6f04eb48e968a76c3043def375c21a8414675e11ae",
        "address": "TDvr6Jpwfp1wDiV7PhaB19YMsMHRSXmY7p",
    },
    {
        "pub_key": b"03436c3e77f7738dcbfc2cfbb6e12e1509979cde41f216eed86c82ab661b5b3fc0",
        "address": "TXJ2Z9VAwDpQ4W6zwTpXxRUpwFVDetPQuC",
    },
    {
        "pub_key": b"02f6cd3a2761360cd7e8c183aca501ee0ce0e42fc270a68aafd153dd06c857a8c4",
        "address": "TNdfXv6WTTyS2ohkTu8YA62WmLTNWqK46i",
    },
    {
        "pub_key": b"0360e11323f918ade5a53bd5ac7171712f019f62e9ad8e0e18ec2b8ca01d4daba4",
        "address": "TF7cowibxyJdMyGtjP2yP7oyN5ZmSMPnWd",
    },
    {
        "pub_key": b"034767fb943ddb893377754ba71e4f82ec15134c7fe4240529d3d0ff473650b210",
        "address": "TYQPvAG6AuzQed8RPuH62pcbZBKj9TkPk1",
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
class TrxAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], TrxAddr.ToAddress(key_bytes))
            self.assertEqual(test["address"], TrxAddr.ToAddress(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, TrxAddr.ToAddress, Ed25519PublicKey(b"000102030405060708090a0b0c0d0e0f"))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, TrxAddr.ToAddress, binascii.unhexlify(test))
