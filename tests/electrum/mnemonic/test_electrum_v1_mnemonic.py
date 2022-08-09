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
    ElectrumV1, ElectrumV1EntropyBitLen, ElectrumV1EntropyGenerator, ElectrumV1Languages, ElectrumV1MnemonicDecoder,
    ElectrumV1MnemonicGenerator, ElectrumV1MnemonicValidator, ElectrumV1SeedGenerator, ElectrumV1WordsNum
)


# Verified with the official Electrum wallet
TEST_VECT = [
    #
    # Basic
    #

    {
        "entropy": b"00000000000000000000000000000000",
        "mnemonic": "like like like like like like like like like like like like",
        "seed": b"7c2548ab89ffea8a6579931611969ffc0ed580ccf6048d4230762b981195abe5",
        "address": "1FHsTashEBUNPQwC1CwVjnKUxzwgw73pU4",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "mnemonic": "funny melt determine funny melt determine funny melt determine funny melt determine",
        "seed": b"91236e0d4ef739d0f897639557fd489e9f41719dc4eede830200bf1d03a31471",
        "address": "1H1brMd7WvSMfASxVLdtwqzHt4d9iAbuCH",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"80808080808080808080808080808080",
        "mnemonic": "aunt tomorrow useless aunt tomorrow useless aunt tomorrow useless aunt tomorrow useless",
        "seed": b"b349a48620cdd8efc550ea503cf1465ea3a0c995a3034837037803b8147c3036",
        "address": "1HWd5Xpf2TY2obM41VW6FPBuB6yS5qxZSV",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"ffffffffffffffffffffffffffffffff",
        "mnemonic": "fail husband howl fail husband howl fail husband howl fail husband howl",
        "seed": b"5c1ced0966cef2d2b5516de1b41f977458e1f49b25042327cf2321f0a9687855",
        "address": "155rdZVaATs7JhCBVMW4V8cX1t1TyDhdve",
        "lang": ElectrumV1Languages.ENGLISH,
    },

    #
    # Some random mnemonics
    #

    {
        "entropy": b"e6914a31dc45fe52a979acde7128cfb4",
        "mnemonic": "evening violence rainbow hit daily mourn hundred rebel dinner war hug blank",
        "seed": b"151d19768f1c2bc0986c276975996bb8e63e0c5bc7779fffe381ec93a10da5ed",
        "address": "1KxCSrMZLH2haDyaZ6VjfgmCx7od6voX8u",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"2d657576503ce5123ee7123fb70444ba",
        "mnemonic": "itself page ourselves size affection listen jaw line deserve silly new inner",
        "seed": b"984894093b641fde81b74d696b606128aec1dbfd6bceb1d28be50f1008217501",
        "address": "1ALEKjmnnG9iA8F59LHNHs5zWKtQmNsSmj",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"69088f48207b7dd5bb962196d7c3980d",
        "mnemonic": "shove two demon remind finish closet two surface already scrape apart there",
        "seed": b"49fd91d7510568781ceaeb8d2b9a76b70bb40e8e3ef17b431ba949279e88ffc1",
        "address": "16TwdCGMqVpC6vSYGBqGYuFTpgLbb78uY3",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"09e4789c5fa2bcb3aaea55d3816c3bee",
        "mnemonic": "mountain ground street creation poet friend ash hook drove breath itself expression",
        "seed": b"7d53043af3962383745a44993dd8cddba9d4d11ca7f24b028933c922c880f5f8",
        "address": "1GTZZ8jc3GbkhFK6bnwHhyerchVb4HEkUf",
        "lang": ElectrumV1Languages.ENGLISH,
    },
    {
        "entropy": b"de445d67f145ae0b5431b8c97aa66ade",
        "mnemonic": "bullet fill awe six pride spread burst vast loud noise bubble accept",
        "seed": b"bdf5d3f1c1e689135cac642f8332b9af1db5d6b0e79da8f7dc701c0c1f42e72d",
        "address": "1MEKcvdCounKbUE8ppRGMyQZYztVbMVaAT",
        "lang": ElectrumV1Languages.ENGLISH,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "like like like like like like like like like like like",
        "exception": ValueError,
    },
    {
        "mnemonic": "like like like like like like like like like like like like like",
        "exception": ValueError,
    },
    # Not existent word
    {
        "mnemonic": "like like notexistent like like like like like like like like like",
        "exception": ValueError,
    },
    {
        "mnemonic": "like like notexistent like like like like like like like like like",
        "lang": None,
        "exception": ValueError,
    },
]


#
# Tests
#
class ElectrumV1MnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"]

            # Test mnemonic generator
            mnemonic = ElectrumV1MnemonicGenerator(lang).FromEntropy(binascii.unhexlify(test["entropy"]))

            self.assertEqual(test["mnemonic"], mnemonic.ToStr())
            self.assertEqual(test["mnemonic"], str(mnemonic))
            self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
            self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())

            # Test mnemonic validator (language specified)
            mnemonic_validator = ElectrumV1MnemonicValidator(lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            # Test mnemonic validator (automatic language detection)
            mnemonic_validator = ElectrumV1MnemonicValidator()
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))

            # Test decoder (language specified)
            entropy = ElectrumV1MnemonicDecoder(lang).Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))
            # Test decoder (automatic language detection)
            entropy = ElectrumV1MnemonicDecoder().Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))

            # Test seed generator
            seed = ElectrumV1SeedGenerator(mnemonic, lang).Generate()
            self.assertEqual(test["seed"], binascii.hexlify(seed))

            # Test address
            self.assertEqual(test["address"], ElectrumV1.FromSeed(seed).GetAddress(0, 0))

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        for test_bit_len in ElectrumV1EntropyBitLen:
            # Test generator
            entropy = ElectrumV1EntropyGenerator(test_bit_len).Generate()
            self.assertEqual(len(entropy), test_bit_len // 8)

            # Compute the expected mnemonic length
            mnemonic_len = (test_bit_len // 32) * 3

            # Generate mnemonic with checksum
            mnemonic = ElectrumV1MnemonicGenerator().FromEntropy(entropy)
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len)

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        for test_bit_len in ElectrumV1EntropyBitLen:
            self.assertRaises(ValueError, ElectrumV1EntropyGenerator, test_bit_len - 1)
            self.assertRaises(ValueError, ElectrumV1EntropyGenerator, test_bit_len + 1)

            # Build a dummy entropy with invalid bit length
            dummy_ent = b"\x00" * ((test_bit_len - 8) // 8)
            self.assertRaises(ValueError, ElectrumV1MnemonicGenerator().FromEntropy, dummy_ent)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        for test_words_num in ElectrumV1WordsNum:
            mnemonic = ElectrumV1MnemonicGenerator().FromWordsNumber(test_words_num)
            self.assertEqual(mnemonic.WordsCount(), test_words_num)

    # Test construction from invalid words number
    def test_from_invalid_words_num(self):
        for test_words_num in ElectrumV1WordsNum:
            self.assertRaises(ValueError, ElectrumV1MnemonicGenerator().FromWordsNumber, test_words_num - 1)
            self.assertRaises(ValueError, ElectrumV1MnemonicGenerator().FromWordsNumber, test_words_num + 1)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else ElectrumV1Languages.ENGLISH

            self.assertFalse(ElectrumV1MnemonicValidator(lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], ElectrumV1MnemonicValidator(lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], ElectrumV1SeedGenerator, test["mnemonic"], lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, ElectrumV1MnemonicGenerator, 0)
        self.assertRaises(TypeError, ElectrumV1MnemonicValidator, 0)
        self.assertRaises(TypeError, ElectrumV1SeedGenerator, "", 0)
