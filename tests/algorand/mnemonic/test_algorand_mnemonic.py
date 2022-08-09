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
    AlgorandEntropyBitLen, AlgorandEntropyGenerator, AlgorandLanguages, AlgorandMnemonicDecoder,
    AlgorandMnemonicGenerator, AlgorandMnemonicValidator, AlgorandSeedGenerator, AlgorandWordsNum, Bip44, Bip44Coins,
    MnemonicChecksumError
)


# Verified with the official Algorand wallet: https://wallet.myalgo.com/
TEST_VECT = [
    #
    # Basic
    #

    {
        "entropy": b"0000000000000000000000000000000000000000000000000000000000000000",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest",
        "address": "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "mnemonic": "useful worth sausage wave year thank winner legal useful worth sausage wave year thank winner legal useful worth sausage wave year thank winner about anxiety",
        "address": "WKUUF72MTBYYX3LW4JKZQ73NLGY2OLJ3FTJFCAAD4YLQVRR2T753AMXUPM",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"8080808080808080808080808080808080808080808080808080808080808080",
        "mnemonic": "avoid acoustic doctor amount absurd cage advice letter avoid acoustic doctor amount absurd cage advice letter avoid acoustic doctor amount absurd cage advice above capital",
        "address": "4VUHW3IRZT5WGKV3V7UEJ6HRNE6RMCVFQIKW5VTO5I4KWXT5DYJJBVVLPI",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract adapt",
        "address": "O2QVSICEU3SPKEJGLPFHHJQE3EFQKKOR35QCXYYKDGUSK5TA2H2Q3YZHOY",
        "lang": AlgorandLanguages.ENGLISH,
    },

    #
    # Some random mnemonics
    #

    {
        "entropy": b"e6914a31dc45fe52a979acde7128cfb4a0f8c1b693fc79529eb97ea12afe027d",
        "mnemonic": "devote clean board fruit wish feed snap property design peace guide area vanish race oval wish execute junk fresh blood fetch sauce trend about obtain",
        "address": "7RADDL36LN3ADNXCKRYB4ALJFVVQ36XTZ5AO43EU2BNJJP5Z47DKMFA22U",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"2d657576503ce5123ee7123fb70444ba076d312d2d51c09d6c0de519b9e584d0",
        "mnemonic": "pizza stereo depth shallow skill lucky delay base tree barrel capital knife sure era harvest eye retreat raven mammal oxygen impulse defense loud absorb giggle",
        "address": "3XDGJWQZ3DU3HVJDBM7XR57VZXRPSFRAY23H4XRXC7A3I5HN5YJSTYJSN4",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"69088f48207b7dd5bb962196d7c3980d66ab57b78f19b11981c91bfc72354707",
        "mnemonic": "artwork destroy cattle rare wife vocal remind canoe version aunt small general fine sting laundry book curtain afford tooth script tourist snap demand abandon become",
        "address": "AW7FV4A5YRSD344UUZPOESB5I4HPGULRQO2FB6BXZNJMO64BETFHV645NM",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"09e4789c5fa2bcb3aaea55d3816c3bee2daeb2ac8348e5ac8ba76224acdecc09",
        "mnemonic": "license toe soda chalk junk provide fetch field denial rare buffalo ten fox coach buddy embrace original concert fatigue economy flame dash example abandon soap",
        "address": "OZXZRQO4BRHTV3IZ74MEUN3NIAMOHA2ZB4V6PCYSIAC3BV4KLCGVJ6NH5I",
        "lang": AlgorandLanguages.ENGLISH,
    },
    {
        "entropy": b"de445d67f145ae0b5431b8c97aa66aded53013945d6818fb44b427522c6a5b0b",
        "mnemonic": "orange insect recipe gallery frame actual melt return float okay crystal fuel giant age uncover hair glide become surface carbon flavor surround food abandon bomb",
        "address": "JTSSH5QVOWUTBWL2UDJY2FNTE7EDR4XLOYGVXXBJ6IPUXK3KB3SNG67HGM",
        "lang": AlgorandLanguages.ENGLISH,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest",
        "exception": ValueError,
    },
    # Wrong checksum
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon legend",
        "exception": MnemonicChecksumError,
    },
    # Not existent word
    {
        "mnemonic": "abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest",
        "exception": ValueError,
    },
    {
        "mnemonic": "abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest",
        "lang": None,
        "exception": ValueError,
    },
]


#
# Tests
#
class AlgorandMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"]

            # Test mnemonic generator
            mnemonic = AlgorandMnemonicGenerator(lang).FromEntropy(binascii.unhexlify(test["entropy"]))

            self.assertEqual(test["mnemonic"], mnemonic.ToStr())
            self.assertEqual(test["mnemonic"], str(mnemonic))
            self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
            self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())

            # Test mnemonic validator (language specified)
            mnemonic_validator = AlgorandMnemonicValidator(lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            # Test mnemonic validator (automatic language detection)
            mnemonic_validator = AlgorandMnemonicValidator()
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))

            # Test decoder (language specified)
            entropy = AlgorandMnemonicDecoder(lang).Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))
            # Test decoder (automatic language detection)
            entropy = AlgorandMnemonicDecoder().Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))

            # Test seed generator (seed is the entropy itself for Algorand)
            seed = AlgorandSeedGenerator(mnemonic, lang).Generate()
            self.assertEqual(test["entropy"], binascii.hexlify(seed))

            # Test address
            bip44_ctx = Bip44.FromPrivateKey(seed, Bip44Coins.ALGORAND)
            self.assertEqual(test["address"], bip44_ctx.PublicKey().ToAddress())

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        for test_bit_len in AlgorandEntropyBitLen:
            # Test generator
            entropy = AlgorandEntropyGenerator(test_bit_len).Generate()
            self.assertEqual(len(entropy), test_bit_len // 8)

            # Compute the expected mnemonic length
            mnemonic_len = (test_bit_len // 32) * 3 + 1

            # Generate mnemonic with checksum
            mnemonic = AlgorandMnemonicGenerator().FromEntropy(entropy)
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len)

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        for test_bit_len in AlgorandEntropyBitLen:
            self.assertRaises(ValueError, AlgorandEntropyGenerator, test_bit_len - 1)
            self.assertRaises(ValueError, AlgorandEntropyGenerator, test_bit_len + 1)

            # Build a dummy entropy with invalid bit length
            dummy_ent = b"\x00" * ((test_bit_len - 8) // 8)
            self.assertRaises(ValueError, AlgorandMnemonicGenerator().FromEntropy, dummy_ent)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        for test_words_num in AlgorandWordsNum:
            mnemonic = AlgorandMnemonicGenerator().FromWordsNumber(test_words_num)
            self.assertEqual(mnemonic.WordsCount(), test_words_num)

    # Test construction from invalid words number
    def test_from_invalid_words_num(self):
        for test_words_num in AlgorandWordsNum:
            self.assertRaises(ValueError, AlgorandMnemonicGenerator().FromWordsNumber, test_words_num - 1)
            self.assertRaises(ValueError, AlgorandMnemonicGenerator().FromWordsNumber, test_words_num + 1)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else AlgorandLanguages.ENGLISH

            self.assertFalse(AlgorandMnemonicValidator(lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], AlgorandMnemonicValidator(lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], AlgorandSeedGenerator, test["mnemonic"], lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, AlgorandMnemonicGenerator, 0)
        self.assertRaises(TypeError, AlgorandMnemonicValidator, 0)
        self.assertRaises(TypeError, AlgorandSeedGenerator, "", 0)
