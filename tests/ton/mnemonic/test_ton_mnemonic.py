# Copyright (c) 2026 Emanuele Bellocchia
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
    TonLanguages,
    TonMnemonic,
    TonMnemonicGenerator,
    TonMnemonicValidator,
    TonSeedGenerator,
    TonSeedTypes,
    TonWordsNum,
)


TEST_VECT = [
    {
        "mnemonic": "ask fossil tragic dune session prize own bundle element shift pony trouble hamster topple mammal estate strike impulse post moment club hard step lamp",
        "passphrase": "",
        "seed_hd": b"1ebeff074cfc42d61e4819f48f86d4a8740c90acd5b515884a2ea58187fe16aa227ab03764349e7942136354c060f2074ed8dceeee45cfdabf0205cf476fb9fc",
        "seed_priv": b"ef1c1bce29e7497157699b1b5365d69f02b30a567f9cc0ab74962c9a466106698909a23c6c00ea8426c40562c21868314496bfe10622a6016333efea30d51562",
        "lang": TonLanguages.ENGLISH,
    },
    {
        "mnemonic": "polar regular twist rose satisfy dove allow prepare frown appear neck ready entry island win turkey consider social muffin door rough maze impact online",
        "passphrase": "",
        "seed_hd": b"fd26ff9457cfbe32f353a76ece6dd81894663ba9b403f29a17d1e836643269d2781b7c76f775c8dea90905d3673551046b46d01aa9a5f255d8d4729cae58aa7c",
        "seed_priv": b"f5c79f584790dd71bb0517c2d25a7106120bda1a50e77cbf50676b922bbef2501b22306bc64d6ce02734ec86368430c83390976d63e1553417efe68f87cd0470",
        "lang": TonLanguages.ENGLISH,
    },
    {
        "mnemonic": "enlist rhythm fortune stove enact effort step labor myself brand clay exercise easy copper chaos gospel holiday enrich stuff twist cement oblige core travel",
        "passphrase": "test",
        "seed_hd": b"f841fb6cf6dbd4fb2d6783057802253b21980f0a96d55f44dbf20725e648fe4b08bf2378a819d8fddf44cc9b1364483a767134abfa442f8e0c29ad8a91935d1f",
        "seed_priv": b"2ae1035120d67a1fa6f69f5c816efcbb9bcbcfb778424dc30a3cbb24612ed3d25d55e30110ceecc5d63503d1410ac8be10eb020d6707c4af9274b337e4f1b08d",
        "lang": TonLanguages.ENGLISH,
    },
    {
        "mnemonic": "wasp salad dice grit crew legal address peanut kingdom demise park patrol caution search usual stumble author inside ginger announce track reunion walnut sausage",
        "passphrase": "test",
        "seed_hd": b"f28193511e5c784674de0652d41d6625064483aa05eca360c55e44572f013a4ead501144dfbb42aad75340824307d34641d2a8091d41f4fce7def987ff954b68",
        "seed_priv": b"2566dacf043a453fc142b7cbdd047001683e79d0df759aa6a841b5077bf7008b2fe71fde062126384e36da9a37c9790467ea1d51d2297d5d9297f13460827d99",
        "lang": TonLanguages.ENGLISH,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "ask fossil tragic dune session prize own bundle element shift pony trouble hamster topple mammal estate strike impulse post moment club hard step",
        "exception": ValueError,
    },
    {
        "mnemonic": "ask fossil tragic dune session prize own bundle element shift pony trouble hamster topple mammal estate strike impulse post moment club hard step lamp step",
        "exception": ValueError,
    },
    # Not existent word
    {
        "mnemonic": "ask fossil tragic dune session prize own bundle element shift pony trouble hamster topple mammal estate strike impulse post moment club hard step notexistent",
        "exception": ValueError,
    },
]


#
# Tests
#
class TonMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"]
            mnemonic = test["mnemonic"]
            passphrase = test["passphrase"]

            # Test mnemonic validator (language specified)
            mnemonic_validator = TonMnemonicValidator(lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic, passphrase))
            mnemonic_validator.Validate(mnemonic, passphrase)
            # Test mnemonic validator (automatic language detection)
            mnemonic_validator = TonMnemonicValidator()
            self.assertTrue(mnemonic_validator.IsValid(mnemonic, passphrase))
            mnemonic_validator.Validate(mnemonic, passphrase)

            # Test seed generator
            seed_hd = TonSeedGenerator(mnemonic, passphrase, lang).Generate(TonSeedTypes.HD_KEY)
            self.assertEqual(test["seed_hd"], binascii.hexlify(seed_hd))

            seed_priv = TonSeedGenerator(mnemonic, passphrase, lang).Generate(TonSeedTypes.PRIVATE_KEY)
            self.assertEqual(test["seed_priv"], binascii.hexlify(seed_priv))

            seed_priv = TonSeedGenerator(mnemonic, passphrase, lang).Generate()
            self.assertEqual(test["seed_priv"], binascii.hexlify(seed_priv))

    # Test mnemonic generator
    def test_generator(self):
        for lang in TonLanguages:
            for words_num in TonWordsNum:
                for passphrase in ["", "test"]:
                    mnemonic = TonMnemonicGenerator(lang).FromWordsNumber(words_num, passphrase)

                    self.assertTrue(isinstance(mnemonic, TonMnemonic))
                    self.assertEqual(words_num, mnemonic.WordsCount())
                    self.assertTrue(TonMnemonicValidator(lang).IsValid(mnemonic, passphrase))

                    self.assertRaises(ValueError, TonMnemonicGenerator(lang).FromWordsNumber, words_num - 1)
                    self.assertRaises(ValueError, TonMnemonicGenerator(lang).FromWordsNumber, words_num + 1)

    # Test validation of a mnemonic with/without a passphrase
    def test_passphrase_validation(self):
        mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
        self.assertFalse(TonMnemonicValidator().IsValid(mnemonic, "test"))
        self.assertRaises(ValueError, TonSeedGenerator, mnemonic, "test")

        mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24, "test")
        self.assertFalse(TonMnemonicValidator().IsValid(mnemonic))
        self.assertRaises(ValueError, TonSeedGenerator, mnemonic)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else TonLanguages.ENGLISH

            self.assertFalse(TonMnemonicValidator(lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], TonMnemonicValidator(lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], TonSeedGenerator, test["mnemonic"], "", lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, TonMnemonicGenerator, 0)
        self.assertRaises(TypeError, TonMnemonicValidator, 0)
        self.assertRaises(TypeError, TonSeedGenerator, "", "", 0)

        mnemonic = TonMnemonicGenerator().FromWordsNumber(TonWordsNum.WORDS_NUM_24)
        self.assertRaises(TypeError, TonSeedGenerator(mnemonic).Generate, 0)
