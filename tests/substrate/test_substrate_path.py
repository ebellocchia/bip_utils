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
    Substrate, SubstrateCoins, SubstratePath, SubstratePathElem, SubstratePathError, SubstratePathParser
)
from tests.substrate.test_substrate import TEST_SEED


# Tests for path elements
TEST_VECT_PATH_ELEM = [
    {
        "elem": "//hard",
        "is_hard": True,
        "chain_code": b"1068617264000000000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "/soft",
        "is_hard": False,
        "chain_code": b"10736f6674000000000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "//StringLongerThan32CharactersForBlake2b",
        "is_hard": True,
        "chain_code": b"87e2788c1c16a2d828b1de38207e5485acd23fe092962bed098b01caeaf642ec",
    },
    {
        "elem": "/255",
        "is_hard": False,
        "chain_code": b"ff00000000000000000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "/65535",
        "is_hard": False,
        "chain_code": b"ffff000000000000000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "/4294967295",
        "is_hard": False,
        "chain_code": b"ffffffff00000000000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "/18446744073709551615",
        "is_hard": False,
        "chain_code": b"ffffffffffffffff000000000000000000000000000000000000000000000000",
    },
    {
        "elem": "/340282366920938463463374607431768211455",
        "is_hard": False,
        "chain_code": b"ffffffffffffffffffffffffffffffff00000000000000000000000000000000",
    },
    {
        "elem": "/115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "is_hard": False,
        "chain_code": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },
]

# Tests for paths
TEST_VECT_PATH = [
    {
        "path": "",
        "parsed": [],
    },
    {
        "path": "//hard",
        "parsed": ["//hard"],
    },
    {
        "path": "//hard/soft",
        "parsed": ["//hard", "/soft"],
    },
    {
        "path": "//hard/soft/0//1",
        "parsed": ["//hard", "/soft", "/0", "//1"],
    },
]

# Tests for path add element
TEST_VECT_ADD_ELEM = [
    {
        "elem": "//hard1",
        "path": "//hard1",
    },
    {
        "elem": SubstratePathElem("//hard2"),
        "path": "//hard1//hard2",
    },
    {
        "elem": "/soft1",
        "path": "//hard1//hard2/soft1",
    },
    {
        "elem": SubstratePathElem("/soft2"),
        "path": "//hard1//hard2/soft1/soft2",
    },
]

# Tests for invalid path elements
TEST_VECT_PATH_ELEM_INVALID = [
    {
        "elem": "/",
        "type": "construction",
    },
    {
        "elem": "//",
        "type": "construction",
    },
    {
        "elem": "///",
        "type": "construction",
    },
    {
        "elem": "hard",
        "type": "construction",
    },
    {
        "elem": "///hard",
        "type": "construction",
    },
    {
        "elem": "value//hard",
        "type": "construction",
    },
    {
        "elem": "//hard/soft",
        "type": "construction",
    },
    {
        "elem": "value//hard/soft",
        "type": "construction",
    },
    {
        "elem": "/115792089237316195423570985008687907853269984665640564039457584007913129639936",
        "type": "chain_code",
    },
]

# Tests for invalid paths
TEST_VECT_PATH_INVALID = [
    "value//hard/soft",
    "value///hard/soft",
    "///hard/soft",
    "//hard///soft",
]


#
# Tests
#
class SubstratePathTests(unittest.TestCase):
    # Test path
    def test_path(self):
        for test in TEST_VECT_PATH:
            # Test construction in different ways
            self.__test_path(test, SubstratePathParser.Parse(test["path"]))
            self.__test_path(test, SubstratePath(test["parsed"]))

    # Test path element
    def test_path_elem(self):
        for test in TEST_VECT_PATH_ELEM:
            path_elem = SubstratePathElem(test["elem"])

            self.assertEqual(test["elem"], path_elem.ToStr())
            self.assertEqual(test["elem"], str(path_elem))
            self.assertEqual(binascii.unhexlify(test["chain_code"]), path_elem.ChainCode())
            self.assertEqual(test["is_hard"], path_elem.IsHard())
            self.assertEqual(test["is_hard"], not path_elem.IsSoft())

    # Test add element
    def test_add_elem(self):
        path = SubstratePath()
        self.assertEqual(0, path.Length())
        self.assertEqual([], path.ToList())
        self.assertEqual("", path.ToStr())

        for test in TEST_VECT_ADD_ELEM:
            path = path.AddElem(test["elem"])
            self.assertEqual(test["path"], path.ToStr())

    # Test invalid paths
    def test_invalid_path(self):
        for test in TEST_VECT_PATH_INVALID:
            self.assertRaises(SubstratePathError, SubstratePathParser.Parse, test)

            self.assertRaises(SubstratePathError, Substrate.FromSeed(TEST_SEED, SubstrateCoins.POLKADOT).DerivePath, test)
            self.assertRaises(SubstratePathError, Substrate.FromSeedAndPath, TEST_SEED, test, SubstrateCoins.POLKADOT)

    # Test invalid path elements
    def test_invalid_path_elem(self):
        for test in TEST_VECT_PATH_ELEM_INVALID:
            if test["type"] == "construction":
                self.assertRaises(SubstratePathError, SubstratePathElem, test["elem"])
            elif test["type"] == "chain_code":
                elem = SubstratePathElem(test["elem"])
                self.assertRaises(SubstratePathError, elem.ChainCode)

    # Test a path object
    def __test_path(self, test, path):
        # Check length
        self.assertEqual(len(test["parsed"]), path.Length())
        # Check string conversion
        self.assertEqual(test["path"], path.ToStr())
        self.assertEqual(test["path"], str(path))

        # Check by iterating
        for idx, elem in enumerate(path):
            test_elem = test["parsed"][idx]

            self.assertEqual(test_elem, str(elem))
            self.assertEqual(test_elem, str(path[idx]))
            self.assertEqual(test_elem, elem.ToStr())

        # Check by converting to list
        for idx, elem in enumerate(path.ToList()):
            self.assertEqual(test["parsed"][idx], elem)

        added_elem = "/added"

        # Try to add element
        new_path = path.AddElem(added_elem)
        self.assertEqual(added_elem, str(new_path[new_path.Length() - 1]))

        new_path = path.AddElem(SubstratePathElem(added_elem))
        self.assertEqual(added_elem, str(new_path[new_path.Length() - 1]))
