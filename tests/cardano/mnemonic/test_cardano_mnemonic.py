# Copyright (c) 2022 Emanuele Bellocchia
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
from bip_utils import CardanoBip39SeedGenerator

# Test vector
TEST_VECT = [
    #
    # Basic 12-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed": b"00000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "seed": b"ffffffffffffffffffffffffffffffff",
    },

    #
    # Basic 18-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "seed": b"000000000000000000000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "seed": b"ffffffffffffffffffffffffffffffffffffffffffffffff",
    },

    #
    # Basic 24-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "seed": b"0000000000000000000000000000000000000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "seed": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },

    #
    # Various
    #
    {
        "mnemonic": "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "seed": b"9e885d952ad362caeb4efe34a8e91bd2",
    },
    {
        "mnemonic": "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "seed": b"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
    },
    {
        "mnemonic": "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "seed": b"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    },
    {
        "mnemonic": "cat swing flag economy stadium alone churn speed unique patch report train",
        "seed": b"23db8160a31d3e0dca3688ed941adbf3",
    },
    {
        "mnemonic": "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "seed": b"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
    },
    {
        "mnemonic": "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "seed": b"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
    },
]


#
# Tests
#
class CardanoMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            seed = CardanoBip39SeedGenerator(test["mnemonic"]).Generate()
            self.assertEqual(test["seed"], binascii.hexlify(seed))

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, CardanoBip39SeedGenerator, "", 0)
