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

import os

# Imports
import random
import unittest

from bip_utils import Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyData, Bip32KeyIndex
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst


#
# Tests
#
class Bip32KeyDataTests(unittest.TestCase):
    # Basic test
    def test_basic(self):
        # Bip32Depth
        self.assertEqual(Bip32Depth.FixedLength(), Bip32KeyDataConst.DEPTH_BYTE_LEN)
        rnd = random.randrange(10)
        depth = Bip32Depth(rnd)
        self.assertEqual(depth.ToInt(), rnd)
        self.assertEqual(int(depth), rnd)
        # Bip32KeyIndex
        self.assertEqual(Bip32KeyIndex.FixedLength(), Bip32KeyDataConst.KEY_INDEX_BYTE_LEN)
        rnd = random.randrange(Bip32KeyDataConst.KEY_INDEX_MAX_VAL)
        key_idx = Bip32KeyIndex(rnd)
        self.assertEqual(key_idx.ToInt(), rnd)
        self.assertEqual(int(key_idx), rnd)
        if key_idx.IsHardened():
            new_key_idx = key_idx.Unharden()
            self.assertEqual(new_key_idx.ToInt(), Bip32KeyIndex.UnhardenIndex(key_idx.ToInt()))
            self.assertFalse(new_key_idx.IsHardened())
        else:
            new_key_idx = key_idx.Harden()
            self.assertEqual(new_key_idx.ToInt(), Bip32KeyIndex.HardenIndex(key_idx.ToInt()))
            self.assertTrue(new_key_idx.IsHardened())
        # Bip32ChainCode
        self.assertEqual(Bip32ChainCode.FixedLength(), Bip32KeyDataConst.CHAINCODE_BYTE_LEN)
        chaincode_bytes = os.urandom(Bip32KeyDataConst.CHAINCODE_BYTE_LEN)
        chaincode = Bip32ChainCode(chaincode_bytes)
        self.assertEqual(chaincode.ToHex(), chaincode_bytes.hex())
        self.assertEqual(str(chaincode), chaincode_bytes.hex())
        self.assertEqual(chaincode.ToBytes(), chaincode_bytes)
        self.assertEqual(bytes(chaincode), chaincode_bytes)
        # Bip32FingerPrint (default)
        self.assertEqual(Bip32FingerPrint.FixedLength(), Bip32KeyDataConst.FINGERPRINT_BYTE_LEN)
        fprint = Bip32FingerPrint()
        self.assertEqual(fprint.ToHex(), Bip32KeyDataConst.FINGERPRINT_MASTER_KEY.hex())
        self.assertEqual(str(fprint), Bip32KeyDataConst.FINGERPRINT_MASTER_KEY.hex())
        self.assertEqual(fprint.ToBytes(), Bip32KeyDataConst.FINGERPRINT_MASTER_KEY)
        self.assertEqual(bytes(fprint), Bip32KeyDataConst.FINGERPRINT_MASTER_KEY)
        self.assertTrue(fprint.IsMasterKey())
        # Bip32FingerPrint (random)
        fprint_bytes = os.urandom(Bip32KeyDataConst.FINGERPRINT_BYTE_LEN)
        fprint = Bip32FingerPrint(fprint_bytes)
        self.assertEqual(fprint.ToHex(), fprint_bytes.hex())
        self.assertEqual(str(fprint), fprint_bytes.hex())
        self.assertEqual(fprint.ToBytes(), fprint_bytes)
        self.assertEqual(bytes(fprint), fprint_bytes)
        self.assertFalse(fprint.IsMasterKey())

        # Bip32KeyData
        key_data = Bip32KeyData(depth, key_idx, chaincode, fprint)

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
        self.assertRaises(ValueError, Bip32ChainCode, b"\x00" * (chaincode_len - 1))
        self.assertRaises(ValueError, Bip32ChainCode, b"\x00" * (chaincode_len + 1))
        # Bip32FingerPrint
        fprint_len = Bip32KeyDataConst.FINGERPRINT_BYTE_LEN
        self.assertRaises(ValueError, Bip32FingerPrint, b"\x00" * (fprint_len - 1))
