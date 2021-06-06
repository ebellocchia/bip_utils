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
from bip_utils import OkexAddr, Ed25519PublicKey, Secp256k1PublicKey

# Some keys randomly taken
TEST_VECT = [
    {
        "pub_key": b"03baf0b46095920af1a8c636cd9d9df37286190607d44ed82688f62c6c002acbc8",
        "address": "ex143pr24a30ml64mzgl74fhyuhrwg82y7vmyse7q",
    },
    {
        "pub_key": b"027bba228d456609587ce5d30f63443f421a3b187f6c53c53ba7626568a1025081",
        "address": "ex1hfh528h34asdtq7t3k7lhsvkhqc32hcypk3gyt",
    },
    {
        "pub_key": b"03ec14157c1bb62c6b8ce10b7379bee621a6f79735b950eaf125913a3da19bdaf9",
        "address": "ex170k75kvpj4urgs98nnlkhhfz90jrulfkq5k8rn",
    },
    {
        "pub_key": b"03b5f6bafd1656dbd1502b7d941d7bed5cfb2d1b479be9506e92752c96c5145965",
        "address": "ex1wj4nhg2k54aersyvjrgkv9js4sq74tajsg6zm0",
    },
    {
        "pub_key": b"03068feb64a09aee06eac40abfabd16574e78108948405cc566f175509e17ebb52",
        "address": "ex1ak63v55f8e765zqk3ucndrzvt29jdjtrkz33f2",
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
class OkexAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], OkexAddr.ToAddress(key_bytes))
            self.assertEqual(test["address"], OkexAddr.ToAddress(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, OkexAddr.ToAddress, Ed25519PublicKey(binascii.unhexlify(b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547")))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, OkexAddr.ToAddress, binascii.unhexlify(test))
