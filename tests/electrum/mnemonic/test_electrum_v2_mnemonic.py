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
import math
import unittest

from bip_utils import (
    BytesUtils, ElectrumV2EntropyBitLen, ElectrumV2EntropyGenerator, ElectrumV2Languages, ElectrumV2MnemonicDecoder,
    ElectrumV2MnemonicGenerator, ElectrumV2MnemonicTypes, ElectrumV2MnemonicValidator, ElectrumV2SeedGenerator,
    ElectrumV2Segwit, ElectrumV2Standard, ElectrumV2WordsNum
)
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import ElectrumV2MnemonicConst


# Verified with the official Electrum wallet
TEST_VECT = [
    #
    # 12-words
    #
    {
        "entropy": b"010c7b98d1ec9c28b1b8d3a88f67dc6818",
        "entropy_final": b"010c7b98d1ec9c28b1b8d3a88f67dc68eb",
        "mnemonic_type": ElectrumV2MnemonicTypes.STANDARD,
        "mnemonic": "buddy immune recycle material point hotel easily order diesel globe differ awkward",
        "seed": b"f0757e2a00a3e70c5042ffb688a9049e0a627f870addef552db6ffde05e8e58db162387a3d257d27e8697c3ba6225a5a9c3ed91571b9db1fdbef6df701d4b381",
        "address": "1XJy9dp4a9LA7sGxLx8ehrwNjdgtqjGwb",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"06ef0f730072f307c3bda36f71e483fb9e",
        "entropy_final": b"06ef0f730072f307c3bda36f71e48416b2",
        "mnemonic_type": ElectrumV2MnemonicTypes.SEGWIT,
        "mnemonic": "stone aware venture warfare egg urge dignity vessel atom slot marble humble",
        "seed": b"82344b5c5fbb817563932bfa4ad649b405215d02d3403b1fe1405fdde82d53471191d2d9342c3a2f06f631d6d23eb7d52df816a132168d081c0cf7b3b13a3e20",
        "address": "bc1q7dm9rjee2uz6e2k3at9fu6hcs7jj57jluz99ly",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"08ad781cf82f79ea4d48c820d63a0dfd20",
        "entropy_final": b"08ad781cf82f79ea4d48c820d63a0e0485",
        "mnemonic_type": ElectrumV2MnemonicTypes.STANDARD_2FA,
        "mnemonic": "mouse day brown aspect motion fall fame ketchup album initial rose member",
        "seed": b"b0014f4ed4dea67cbc2f2befe40142ea7d593f245d5721c309623be948cc9b155ce4d11d518e544c1f6484c103bbefff54bd79f46e5ad49a1d561155b9bb66c3",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"0db40bd4f67e1bf8d05c663c1e24634204",
        "entropy_final": b"0db40bd4f67e1bf8d05c663c1e24634a4b",
        "mnemonic_type": ElectrumV2MnemonicTypes.SEGWIT_2FA,
        "mnemonic": "enact minor banana sea small blade shoot brief sound fatigue album swap",
        "seed": b"94ba8703a973beb4040e11581d5b9a1f5b2c201fcd201fcdc07d5bee127853299f5ed95a12d35b69dce55836ab59b2e614598469dd4a0435b0985e3dc8ddc104",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    #
    # 24-words
    #
    {
        "entropy": b"e876bcea61af457f4ea4d299b32464da841b0cd66dbc20acb05f0587c75240a606",
        "entropy_final": b"e876bcea61af457f4ea4d299b32464da841b0cd66dbc20acb05f0587c75240a91d",
        "mnemonic_type": ElectrumV2MnemonicTypes.STANDARD,
        "mnemonic": "casual actor powder ladder arch blind grain camera resource fluid major double relax bomb odor often olympic dentist sausage violin select dentist remove trick",
        "seed": b"634ac54db0c8590cbc98ceb73f81fc4c25c1bec62c6d7d3fdf19968f337dfabe9ace7a6bbe1e20db6213d166e1ccf82f7329a1e461e353ef1e25e020bb730013",
        "address": "145AcZnwvgTyaaCMcLBfAP3SD1Z1EMaHuJ",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"46cf86bb0b6a3a79296358ea4d0014e03400cc52ad49a0f087bf36aa50a786411e",
        "entropy_final": b"46cf86bb0b6a3a79296358ea4d0014e03400cc52ad49a0f087bf36aa50a786441b",
        "mnemonic_type": ElectrumV2MnemonicTypes.SEGWIT,
        "mnemonic": "lock boil fatigue pink hood used loud path powder enjoy great divorce scatter ahead gym tumble help pitch develop photo bitter put label egg",
        "seed": b"e67d8004f878e665909247b06695319dce99413cdeba15869e311fd53e59fa3bf2e521e046793d4cf96791e1bec4b8afe761cee7735628c21198919c65f2d864",
        "address": "bc1qmgq4u2r5leyrdhc678sqtvl5ef9nzfx4cmjwdm",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"58d603a6b35da26206d9ea9675425a1c1bb342cec1b83425895038892f46a69f20",
        "entropy_final": b"58d603a6b35da26206d9ea9675425a1c1bb342cec1b83425895038892f46a6a239",
        "mnemonic_type": ElectrumV2MnemonicTypes.STANDARD_2FA,
        "mnemonic": "elbow once person napkin illegal favorite clump crouch damage deposit pause robot deal notable present nose diary bread country surface grit trust quote flee",
        "seed": b"48e9c28f2fd531f2f5a0ca519877bba3f3cd3ef2c60173b7b4322d8c8129aec58fdeed21904c874e515fec16c14528c894412b708dd251bdcc442b2b6b1630b0",
        "lang": ElectrumV2Languages.ENGLISH,
    },
    {
        "entropy": b"321f7b2cf233530027e6ce79085e37928a647b44c1055904a858400e2369bc03a4",
        "entropy_final": b"321f7b2cf233530027e6ce79085e37928a647b44c1055904a858400e2369bc0a0f",
        "mnemonic_type": ElectrumV2MnemonicTypes.SEGWIT_2FA,
        "mnemonic": "draft usual regular timber length bid census flip camera basic diet play celery mistake drill jungle supply panel length cry tongue sleep wink craft",
        "seed": b"ffc3be5af4a0410c9cd700d8a6cd9e6567fb429c16254f983271d1c43553821496d433fb8839b1931250986a886d81d330779375169eb11d8ef1ab18ee622178",
        "lang": ElectrumV2Languages.ENGLISH,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "buddy immune recycle material point hotel easily order diesel globe differ",
        "exception": ValueError,
    },
    # Not existent word
    {
        "mnemonic": "buddy notexistent recycle material point hotel easily order diesel globe differ awkward",
        "exception": ValueError,
    },
    {
        "mnemonic": "buddy notexistent recycle material point hotel easily order diesel globe differ awkward",
        "lang": None,
        "exception": ValueError,
    },
    # Wrong language
    {
        "mnemonic": "buddy immune recycle material point hotel easily order diesel globe differ awkward",
        "lang": ElectrumV2Languages.SPANISH,
        "exception": ValueError,
    },
    # Invalid mnemonic type
    {
        "mnemonic": "safe engage car mad drill film envelope boy journey arm miss angry",
        "exception": ValueError,
    },
    # BIP39 mnemonic
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "exception": ValueError,
    },
    # Electrum v1 mnemonic
    {
        "mnemonic": "like like like like like like like like like like like like",
        "exception": ValueError,
    },
]


#
# Tests
#
class ElectrumV2MnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"]

            # Test mnemonic generator
            mnemonic = ElectrumV2MnemonicGenerator(test["mnemonic_type"], lang).FromEntropy(binascii.unhexlify(test["entropy"]))

            self.assertEqual(test["mnemonic"], mnemonic.ToStr())
            self.assertEqual(test["mnemonic"], str(mnemonic))
            self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
            self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())

            # Test mnemonic validator (language specified, all mnemonic types)
            mnemonic_validator = ElectrumV2MnemonicValidator(lang=lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            # Test mnemonic validator (automatic language detection, all mnemonic types)
            mnemonic_validator = ElectrumV2MnemonicValidator()
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            # Test mnemonic validator (mnemonic type specified)
            mnemonic_validator = ElectrumV2MnemonicValidator(mnemonic_type=test["mnemonic_type"])
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))

            # Test decoder (language specified, all mnemonic types)
            entropy = ElectrumV2MnemonicDecoder(lang=lang).Decode(mnemonic)
            self.assertEqual(test["entropy_final"], binascii.hexlify(entropy))
            # Test decoder (automatic language detection, all mnemonic types)
            entropy = ElectrumV2MnemonicDecoder().Decode(mnemonic)
            self.assertEqual(test["entropy_final"], binascii.hexlify(entropy))
            # Test decoder (mnemonic type specified)
            entropy = ElectrumV2MnemonicDecoder(mnemonic_type=test["mnemonic_type"]).Decode(mnemonic)
            self.assertEqual(test["entropy_final"], binascii.hexlify(entropy))

            # Test seed generator
            seed = ElectrumV2SeedGenerator(mnemonic, lang).Generate()
            self.assertEqual(test["seed"], binascii.hexlify(seed))

            # Test address
            if test["mnemonic_type"] == ElectrumV2MnemonicTypes.STANDARD:
                self.assertEqual(test["address"], ElectrumV2Standard.FromSeed(seed).GetAddress(0, 0))
            elif test["mnemonic_type"] == ElectrumV2MnemonicTypes.SEGWIT:
                self.assertEqual(test["address"], ElectrumV2Segwit.FromSeed(seed).GetAddress(0, 0))

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        for test_bit_len in ElectrumV2EntropyBitLen:
            # Test generator
            entropy = ElectrumV2EntropyGenerator(test_bit_len).Generate()
            entropy_bit_len = math.ceil(math.log(BytesUtils.ToInteger(entropy), 2))
            self.assertTrue(test_bit_len - ElectrumV2MnemonicConst.WORD_BIT_LEN <= entropy_bit_len <= test_bit_len)

            # Compute the expected mnemonic length
            mnemonic_len = test_bit_len // 11

            # Generate mnemonic with checksum
            mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy(entropy)
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len)

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        for test_bit_len in ElectrumV2EntropyBitLen:
            self.assertRaises(ValueError, ElectrumV2EntropyGenerator, test_bit_len - ElectrumV2MnemonicConst.WORD_BIT_LEN - 1)
            self.assertRaises(ValueError, ElectrumV2EntropyGenerator, test_bit_len + 1)

            # Build a dummy entropy with invalid bit length
            dummy_ent = b"\x00" * ((test_bit_len - 8) // 8)
            self.assertRaises(ValueError, ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy, dummy_ent)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        for test_words_num in ElectrumV2WordsNum:
            while True:
                try:
                    mnemonic = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber(test_words_num)
                    self.assertEqual(mnemonic.WordsCount(), test_words_num)
                    break
                except ValueError:
                    continue

    # Test construction from invalid words number
    def test_from_invalid_words_num(self):
        for test_words_num in ElectrumV2WordsNum:
            self.assertRaises(ValueError, ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber, test_words_num - 1)
            self.assertRaises(ValueError, ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromWordsNumber, test_words_num + 1)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else ElectrumV2Languages.ENGLISH

            self.assertFalse(ElectrumV2MnemonicValidator(lang=lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], ElectrumV2MnemonicValidator(lang=lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], ElectrumV2SeedGenerator, test["mnemonic"], lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, ElectrumV2MnemonicGenerator, ElectrumV2MnemonicTypes.STANDARD, 0)
        self.assertRaises(TypeError, ElectrumV2MnemonicGenerator, 0, ElectrumV2Languages.ENGLISH)
        self.assertRaises(TypeError, ElectrumV2MnemonicValidator, ElectrumV2MnemonicTypes.STANDARD, 0)
        self.assertRaises(TypeError, ElectrumV2MnemonicValidator, 0, ElectrumV2Languages.ENGLISH)
        self.assertRaises(TypeError, ElectrumV2SeedGenerator, "", 0)
        # Fail to generate a valid mnemonic (entropy with too few bits)
        self.assertRaises(ValueError, ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy, binascii.unhexlify(b"00000000000000000000000000000000"))
