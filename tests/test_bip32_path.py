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
from bip_utils import (
    Bip32PathError, Bip32PathParser, Bip32Path, Bip32Utils,
    Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip, Bip32Nist256p1, Bip32Secp256k1,
)

# Tests for paths
TEST_VECT_PATH = [
    {
        "path": "m",
        "parsed": [],
        "to_str": "",
    },
    {
        "path": "m/",
        "parsed": [],
        "to_str": "",
    },
    {
        "path": "m/  0/1",
        "parsed": [0, 1],
        "to_str": "0/1",
    },
    {
        "path": "m/0  /1'",
        "parsed": [0, Bip32Utils.HardenIndex(1)],
        "to_str": "0/1'",
    },
    {
        "path": "m/0  /1p",
        "parsed": [0, Bip32Utils.HardenIndex(1)],
        "to_str": "0/1'",
    },
    {
        "path": "m/0'/1'/2/",
        "parsed": [Bip32Utils.HardenIndex(0), Bip32Utils.HardenIndex(1), 2],
        "to_str": "0'/1'/2",
    },
    {
        "path": "m/0p/1p/2/",
        "parsed": [Bip32Utils.HardenIndex(0), Bip32Utils.HardenIndex(1), 2],
        "to_str": "0'/1'/2",
    },
    {
        "path": "0",
        "parsed": [0],
        "to_str": "0",
    },
    {
        "path": "0/",
        "parsed": [0],
        "to_str": "0",
    },
    {
        "path": "0'/1'/2",
        "parsed": [Bip32Utils.HardenIndex(0), Bip32Utils.HardenIndex(1), 2],
        "to_str": "0'/1'/2",
    },
    {
        "path": "0p/1p/2",
        "parsed": [Bip32Utils.HardenIndex(0), Bip32Utils.HardenIndex(1), 2],
        "to_str": "0'/1'/2",
    },
]

# Tests for invalid paths
TEST_VECT_PATH_INVALID = [
    "",
    "mm",
    "m//",
    "n/",
    "mm/0",
    "m/0''",
    "m/0pp",
    "m/0'0/1",
    "m/0p0/1",
    "m/a/1",
    "m/0 1/1",
    "m/0//1/1",
    "0/a/1",
    "0//1/1",
    "0/1/4294967296",
]


#
# Bip32 path tests
#
class Bip32PathTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT_PATH:
            # Test construction in different ways
            self.__test_path(test, Bip32PathParser.Parse(test["path"]))
            self.__test_path(test, Bip32Path(test["parsed"]))

    # Test invalid paths
    def test_invalid_paths(self):
        seed = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f")

        for test in TEST_VECT_PATH_INVALID:
            self.assertRaises(Bip32PathError, Bip32PathParser.Parse, test)

            self.assertRaises(Bip32PathError, Bip32Ed25519Slip.FromSeed(seed).DerivePath, test)
            self.assertRaises(Bip32PathError, Bip32Ed25519Slip.FromSeedAndPath, seed, test)

            self.assertRaises(Bip32PathError, Bip32Ed25519Blake2bSlip.FromSeed(seed).DerivePath, test)
            self.assertRaises(Bip32PathError, Bip32Ed25519Blake2bSlip.FromSeedAndPath, seed, test)

            self.assertRaises(Bip32PathError, Bip32Nist256p1.FromSeed(seed).DerivePath, test)
            self.assertRaises(Bip32PathError, Bip32Nist256p1.FromSeedAndPath, seed, test)

            self.assertRaises(Bip32PathError, Bip32Secp256k1.FromSeed(seed).DerivePath, test)
            self.assertRaises(Bip32PathError, Bip32Secp256k1.FromSeedAndPath, seed, test)

    # Test a path object
    def __test_path(self, test, path):
        # Check length
        self.assertEqual(len(test["parsed"]), path.Length())
        # Check string conversion
        self.assertEqual(test["to_str"], path.ToStr())
        self.assertEqual(test["to_str"], str(path))

        # Check by iterating
        for idx, elem in enumerate(path):
            test_elem = test["parsed"][idx]

            self.assertEqual(test_elem, int(elem))
            self.assertEqual(test_elem, int(path[idx]))
            self.assertEqual(test_elem, elem.ToInt())
            self.assertEqual(Bip32Utils.IsHardenedIndex(test_elem), elem.IsHardened())

        # Check by converting to list
        for idx, elem in enumerate(path.ToList()):
            self.assertEqual(test["parsed"][idx], elem)
