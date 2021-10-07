# Copyright (c) 2021 Emanuele Bellocchia
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
from bip_utils import Bip32ChainCode, Bip32Depth, Bip32KeyIndex, Bip32FingerPrint, Bip32KeyNetVersions
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst


#
# Tests
#
class Bip32KeyDataTests(unittest.TestCase):
    # Test for operators
    def test_operators(self):
        self.assertTrue(Bip32Depth(1) < Bip32Depth(2))
        self.assertTrue(Bip32Depth(1) < 2)
        self.assertTrue(Bip32Depth(2) > Bip32Depth(1))
        self.assertTrue(Bip32Depth(2) > 1)
        self.assertTrue(Bip32Depth(1) == Bip32Depth(1))
        self.assertTrue(Bip32Depth(1) == 1)
        self.assertTrue(int(Bip32Depth(1)) == 1)
        self.assertTrue(Bip32KeyIndex(1) == Bip32KeyIndex(1))
        self.assertTrue(Bip32KeyIndex(1) == 1)
        self.assertTrue(int(Bip32KeyIndex(1)) == 1)

    # Test invalid parameters
    def test_invalid_parameters(self):
        # Bip32Depth
        self.assertRaises(ValueError, Bip32Depth, -1)
        self.assertRaises(TypeError, Bip32Depth(0).__eq__, b"\x00")
        # Bip32KeyIndex
        self.assertRaises(ValueError, Bip32KeyIndex, -1)
        self.assertRaises(ValueError, Bip32KeyIndex, Bip32KeyDataConst.KEY_INDEX_MAX_VAL + 1)
        self.assertRaises(TypeError, Bip32KeyIndex(0).__eq__, b"\x00")
        # Bip32ChainCode
        chaincode_len = Bip32KeyDataConst.CHAINCODE_BYTE_LEN
        self.assertRaises(ValueError, Bip32ChainCode,  b"\x00" * (chaincode_len - 1))
        self.assertRaises(ValueError, Bip32ChainCode,  b"\x00" * (chaincode_len + 1))
        # Bip32FingerPrint
        fprint_len = Bip32KeyDataConst.FINGERPRINT_BYTE_LEN
        self.assertRaises(ValueError, Bip32FingerPrint,  b"\x00" * (fprint_len - 1))
        # Bip32KeyNetVersions
        net_ver_len = Bip32KeyDataConst.KEY_NET_VERSION_LEN
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00" * (net_ver_len - 1), b"\x00\x00\x00\x00")
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00" * (net_ver_len + 1), b"\x00\x00\x00\x00")
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00\x00\x00\x00", b"\x00" * (net_ver_len - 1))
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00\x00\x00\x00", b"\x00" * (net_ver_len + 1))
