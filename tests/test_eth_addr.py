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
from .test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, TEST_ED25519_COMPR_PUB_KEY

# Some random public keys
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


#
# Tests
#
class EthAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], EthAddr.EncodeKey(key_bytes))
            self.assertEqual(test["address"], EthAddr.EncodeKey(Secp256k1PublicKey(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        # Test with invalid key type
        self.assertRaises(TypeError, EthAddr.EncodeKey, Ed25519PublicKey(binascii.unhexlify(TEST_ED25519_COMPR_PUB_KEY)))
        # Test vector
        for test in TEST_VECT_SECP256K1_PUB_KEY_INVALID:
            self.assertRaises(ValueError, EthAddr.EncodeKey, binascii.unhexlify(test))
