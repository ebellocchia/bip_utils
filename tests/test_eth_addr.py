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
from bip_utils import EthAddr, Ed25519PublicKey, Secp256k1PublicKey

# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECT = [
    {
        "pub_key": b"03c41826497a000dd077b3becc10bea5765651c30c37e7bd63ed8562f919720126",
        "address": "0x4d46542bdA7ff01f583e8459125c91D56D2426Cf",
    },
    {
        "pub_key": b"02d72bce774eb5d79384da08c3080ce3bd7996843a7f3efc008a5c45449aab3b0f",
        "address": "0x8C5F5279DD5a5deE331d629620FE6f3e7c73d21e",
    },
    {
        "pub_key": b"027c323f3d80fa0c4891b3a36c3b2790cd04705bc8c66b79f356cc5c304d3eb45b",
        "address": "0x8BC53Cd1c3ba83bd0D11F2F4Bfe0819Be8fb9794",
    },
    {
        "pub_key": b"0226c4d55f5437ad010a6fb1cb6b7c37731a31516c77e5403af3b36fc80dfd2c59",
        "address": "0xA2cA1D082016421489b7891091CA1CF0D2d1220e",
    },
    {
        "pub_key": b"0261d015de607c9b8cfb77f658fabe6af3c7d6865740169026f2f2e95b6e5db14d",
        "address": "0xCaAB0bbEDD3d903832053F4e21CCD6DF48A66870",
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
class EthAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], EthAddr.ToAddress(key_bytes))
            self.assertEqual(test["address"], EthAddr.ToAddress(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, EthAddr.ToAddress, Ed25519PublicKey(binascii.unhexlify(b"00e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547")))
        # Test vector
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, EthAddr.ToAddress, binascii.unhexlify(test))
