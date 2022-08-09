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

from bip_utils import CardanoByronLegacySeedGenerator, CardanoIcarusSeedGenerator


# Test vector
TEST_VECT = [
    #
    # Basic 12-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed_byron_old": b"dfee64f10fd452c2882951ef64eeb43880aa4304fd11110a2f1b13913f258a9d",
        "seed_icarus": b"00000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "seed_byron_old": b"0e1f4c3952ee805e75a7f6c5d7011e0f7b9bbd6db1d4fe728494cf4b864bb37b",
        "seed_icarus": b"ffffffffffffffffffffffffffffffff",
    },

    #
    # Basic 18-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "seed_byron_old": b"6fb60bd4f3984308ad55aea9589738fed1cb5a7ef4a527ca767e970b9c03674c",
        "seed_icarus": b"000000000000000000000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "seed_byron_old": b"0b4c35313154d77fa759bc3b948f40742af8ba0fcad319dfcd75b4d2c1c876df",
        "seed_icarus": b"ffffffffffffffffffffffffffffffffffffffffffffffff",
    },

    #
    # Basic 24-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "seed_byron_old": b"2100e0352f0d73777a4442c7468c4aaf73b3bb99ec93310bcff8330dad87b051",
        "seed_icarus": b"0000000000000000000000000000000000000000000000000000000000000000",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "seed_byron_old": b"3ccc039827a913c2560edff769eccdd713c530d45d79f222a1a78f0b4114383f",
        "seed_icarus": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },

    #
    # Various
    #
    {
        "mnemonic": "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "seed_byron_old": b"f2304cc22f2c7af140258cc8bbed8918687e84fa97ab83633110533b38a27f9a",
        "seed_icarus": b"9e885d952ad362caeb4efe34a8e91bd2",
    },
    {
        "mnemonic": "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "seed_byron_old": b"9cae030bde3bc2c27d1c93731cb04a966ca85b4e154ab2350bb22943fef80aba",
        "seed_icarus": b"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
    },
    {
        "mnemonic": "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "seed_byron_old": b"6793e44febd94f651b7c138c0f2db39cec3fef2195dfbe751210441f08ecc3d6",
        "seed_icarus": b"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    },
    {
        "mnemonic": "cat swing flag economy stadium alone churn speed unique patch report train",
        "seed_byron_old": b"a26585a8ec436b3ce040dbff4056c1495f9c17650ee611dc6362548285b2e58c",
        "seed_icarus": b"23db8160a31d3e0dca3688ed941adbf3",
    },
    {
        "mnemonic": "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "seed_byron_old": b"b043eafc1b9e6e2d1248452e5a0379037ecc0be896020071ce8e31d7fb37ba1b",
        "seed_icarus": b"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
    },
    {
        "mnemonic": "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "seed_byron_old": b"3d3ecf142d96a1054024187c716aa7cc80861f6ef6578bcee70aa1a09c0b95b3",
        "seed_icarus": b"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
    },
]


#
# Tests
#
class CardanoMnemonicTests(unittest.TestCase):
    # Run all tests in test vector for Byron legacy seed generation
    def test_vector_byron_legacy(self):
        for test in TEST_VECT:
            seed = CardanoByronLegacySeedGenerator(test["mnemonic"]).Generate()
            self.assertEqual(test["seed_byron_old"], binascii.hexlify(seed))

    # Run all tests in test vector for Icarus seed generation
    def test_vector_icarus(self):
        for test in TEST_VECT:
            seed = CardanoIcarusSeedGenerator(test["mnemonic"]).Generate()
            self.assertEqual(test["seed_icarus"], binascii.hexlify(seed))

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, CardanoByronLegacySeedGenerator, "", 0)
        self.assertRaises(TypeError, CardanoIcarusSeedGenerator, "", 0)
