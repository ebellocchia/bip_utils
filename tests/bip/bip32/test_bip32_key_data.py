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
import os
import unittest
from bip_utils import Bip32ChainCode, Bip32Depth, Bip32KeyIndex, Bip32FingerPrint, Bip32KeyNetVersions, Bip32KeyData
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst


#
# Tests
#
class Bip32KeyDataTests(unittest.TestCase):
    # Basic test
    def test_basic(self):
        # Bip32Depth
        depth = Bip32Depth(1)
        self.assertEqual(depth.ToInt(), 1)
        self.assertEqual(int(depth), 1)
        # Bip32KeyIndex
        key_idx = Bip32KeyIndex(2)
        self.assertEqual(key_idx.ToInt(), 2)
        self.assertEqual(int(key_idx), 2)
        # Bip32ChainCode
        chaincode_bytes = os.urandom(Bip32KeyDataConst.CHAINCODE_BYTE_LEN)
        chaincode = Bip32ChainCode(chaincode_bytes)
        self.assertEqual(chaincode.ToHex(), chaincode_bytes.hex())
        self.assertEqual(str(chaincode), chaincode_bytes.hex())
        self.assertEqual(chaincode.ToBytes(), chaincode_bytes)
        self.assertEqual(bytes(chaincode), chaincode_bytes)
        # Bip32FingerPrint (default)
        fprint = Bip32FingerPrint()
        self.assertEqual(fprint.ToHex(), Bip32KeyDataConst.MASTER_FINGERPRINT.hex())
        self.assertEqual(str(fprint), Bip32KeyDataConst.MASTER_FINGERPRINT.hex())
        self.assertEqual(fprint.ToBytes(), Bip32KeyDataConst.MASTER_FINGERPRINT)
        self.assertEqual(bytes(fprint), Bip32KeyDataConst.MASTER_FINGERPRINT)
        self.assertTrue(fprint.IsMasterKey())
        # Bip32FingerPrint (random)
        fprint_bytes = os.urandom(Bip32KeyDataConst.FINGERPRINT_BYTE_LEN)
        fprint = Bip32FingerPrint(fprint_bytes)
        self.assertEqual(fprint.ToHex(), fprint_bytes.hex())
        self.assertEqual(str(fprint), fprint_bytes.hex())
        self.assertEqual(fprint.ToBytes(), fprint_bytes)
        self.assertEqual(bytes(fprint), fprint_bytes)
        self.assertFalse(fprint.IsMasterKey())
        # Bip32KeyNetVersions
        key_net_ver_priv = os.urandom(Bip32KeyDataConst.KEY_NET_VERSION_LEN)
        key_net_ver_pub = os.urandom(Bip32KeyDataConst.KEY_NET_VERSION_LEN)
        key_net_ver = Bip32KeyNetVersions(key_net_ver_priv, key_net_ver_pub)
        self.assertEqual(key_net_ver.Length(), Bip32KeyDataConst.KEY_NET_VERSION_LEN)
        self.assertEqual(key_net_ver.Public(), key_net_ver_priv)
        self.assertEqual(key_net_ver.Private(), key_net_ver_pub)

        # Bip32KeyData
        key_data = Bip32KeyData(key_net_ver, depth, key_idx, chaincode, fprint)

        self.assertEqual(key_data.KeyNetVersions(), key_net_ver)
        self.assertEqual(key_data.KeyNetVersions().Public(), key_net_ver.Public())
        self.assertEqual(key_data.KeyNetVersions().Private(), key_net_ver.Private())
        self.assertEqual(key_data.Depth(), depth)
        self.assertEqual(key_data.Depth().ToInt(), depth.ToInt())
        self.assertEqual(key_data.Index(), key_idx)
        self.assertEqual(key_data.Index().ToInt(), key_idx.ToInt())
        self.assertEqual(key_data.ChainCode(), chaincode)
        self.assertEqual(key_data.ChainCode().ToBytes(), chaincode.ToBytes())
        self.assertEqual(key_data.ParentFingerPrint(), fprint)
        self.assertFalse(key_data.ParentFingerPrint().IsMasterKey())

    # Test for operators
    def test_operators(self):
        self.assertTrue(Bip32Depth(1) < Bip32Depth(2))
        self.assertTrue(Bip32Depth(1) < 2)
        self.assertTrue(Bip32Depth(2) > Bip32Depth(1))
        self.assertTrue(Bip32Depth(2) > 1)
        self.assertTrue(Bip32Depth(1) == Bip32Depth(1))
        self.assertTrue(Bip32Depth(1) == 1)
        self.assertTrue(Bip32KeyIndex(1) == Bip32KeyIndex(1))
        self.assertTrue(Bip32KeyIndex(1) == 1)

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
