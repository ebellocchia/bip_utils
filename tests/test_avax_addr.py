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
from bip_utils import AvaxChainTypes, AvaxPChainAddr, AvaxXChainAddr, Secp256k1

# Some keys randomly taken (verified with Avax wallet)
TEST_VECT = [
    {
        "pub_key": b"02add530ea489143b936d2430e8412182984cdb26c020ce18ddc34dbf24a442b7d",
        "chain": AvaxChainTypes.AVAX_X_CHAIN,
        "address": "X-avax123ghjvxx49h87g0vk26c97ca8x3v44g5n9mzha",
    },
    {
        "pub_key": b"03465789245ff8a454efc9a72608521f30bcc49e35f1bf26272d0a6cb7a7b91876",
        "chain": AvaxChainTypes.AVAX_X_CHAIN,
        "address": "X-avax164klxn22zr2g4q4m3k03zy8skrpgrt36sqm5r4",
    },
    {
        "pub_key": b"03a90de501b386356e40d9800431f06698241414590498903b80f0aeb184dfa537",
        "chain": AvaxChainTypes.AVAX_P_CHAIN,
        "address": "P-avax14q4ugdl65sagjx4as20fuqf37ecaeadcqm96zt",
    },
    {
        "pub_key": b"0317e4b698b4e370ced9fec7c02bfd5c56055e07db49fdc623b1545eb7a61a1287",
        "chain": AvaxChainTypes.AVAX_P_CHAIN,
        "address": "P-avax1e4wshkjvqpfcuu86acl69xad8sl7zsgg723xu3",
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
class AvaxAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            cls = AvaxXChainAddr if test["chain"] == AvaxChainTypes.AVAX_X_CHAIN else AvaxPChainAddr
            self.assertEqual(test["address"], cls.ToAddress(key_bytes))
            self.assertEqual(test["address"], cls.ToAddress(Secp256k1.PublicKeyFromBytes(key_bytes)))

    # Test invalid keys
    def test_invalid_keys(self):
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, AvaxPChainAddr.ToAddress, binascii.unhexlify(test))
            self.assertRaises(ValueError, AvaxXChainAddr.ToAddress, binascii.unhexlify(test))
