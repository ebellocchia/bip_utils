# Copyright (c) 2020 Emanuele Bellocchia
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
from bip_utils import EntropyGenerator, Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39SeedGenerator, Bip39ChecksumError


# Tests from BIP39 page
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
TEST_VECTOR = \
    [
        {
            "entropy"  : b"00000000000000000000000000000000",
            "mnemonic" :  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "seed"     : b"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        },
        {
            "entropy"  : b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "mnemonic" :  "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "seed"     : b"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        },
        {
            "entropy"  : b"80808080808080808080808080808080",
            "mnemonic" :  "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "seed"     : b"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        },
        {
            "entropy"  : b"ffffffffffffffffffffffffffffffff",
            "mnemonic" :  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "seed"     : b"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        },
        {
            "entropy"  : b"000000000000000000000000000000000000000000000000",
            "mnemonic" :  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "seed"     : b"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        },
        {
            "entropy"  : b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "mnemonic" :  "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "seed"     : b"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        },
        {
            "entropy"  : b"808080808080808080808080808080808080808080808080",
            "mnemonic" :  "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "seed"     : b"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        },
        {
            "entropy"  : b"ffffffffffffffffffffffffffffffffffffffffffffffff",
            "mnemonic" :  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "seed"     : b"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        },
        {
            "entropy"  : b"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "mnemonic" :  "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "seed"     : b"fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        },
        {
            "entropy"  : b"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "mnemonic" :  "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "seed"     : b"7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        },
    ]

# Tests passphrase
TEST_PASSPHRASE = "TREZOR"

# Tests for invalid mnemonics
TEST_VECTOR_INVALID_MNEMONIC = \
    [
        # Wrong length
        {
            "mnemonic"  : "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            "exception" : ValueError,
        },
        # Wrong checksum
        {
            "mnemonic"  : "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon any",
            "exception" : Bip39ChecksumError,
        },
        # Not existent word
        {
            "mnemonic"  : "abandon abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon about",
            "exception" : ValueError,
        },
    ]

# Bit lengths for entropy tests
TEST_VECTOR_ENTROPY_BITS = \
    [
        { "bit_len" : 128, "is_valid": True},
        { "bit_len" : 160, "is_valid": True},
        { "bit_len" : 192, "is_valid": True},
        { "bit_len" : 224, "is_valid": True},
        { "bit_len" : 256, "is_valid": True},
        { "bit_len" : 119, "is_valid": False},
        { "bit_len" : 158, "is_valid": False},
        { "bit_len" : 191, "is_valid": False},
        { "bit_len" : 234, "is_valid": False},
        { "bit_len" : 266, "is_valid": False},
    ]

# Words number for word tests
TEST_VECTOR_WORDS_NUM = \
    [
        { "words_num" : 12, "is_valid" : True},
        { "words_num" : 15, "is_valid" : True},
        { "words_num" : 18, "is_valid" : True},
        { "words_num" : 21, "is_valid" : True},
        { "words_num" : 24, "is_valid" : True},
        { "words_num" : 11, "is_valid" : False},
        { "words_num" : 16, "is_valid" : False},
        { "words_num" : 19, "is_valid" : False},
        { "words_num" : 25, "is_valid" : False},
    ]

#
# Tests
#
class Bip39Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            # Test mnemonic generator
            mnemonic = Bip39MnemonicGenerator.FromEntropy(binascii.unhexlify(test["entropy"]))

            self.assertEqual(test["mnemonic"], mnemonic)

            # Test mnemonic validator using string
            bip39_mnemonic_validator = Bip39MnemonicValidator(mnemonic)
            entropy = bip39_mnemonic_validator.GetEntropy()

            self.assertEqual(test["entropy"], binascii.hexlify(entropy))
            self.assertTrue(bip39_mnemonic_validator.Validate())

            # Test mnemonic validator using list
            bip39_mnemonic_validator = Bip39MnemonicValidator(mnemonic.split(" "))
            entropy = bip39_mnemonic_validator.GetEntropy()

            self.assertEqual(test["entropy"], binascii.hexlify(entropy))
            self.assertTrue(bip39_mnemonic_validator.Validate())

            # Test seed generator
            seed = Bip39SeedGenerator(mnemonic).Generate(TEST_PASSPHRASE)

            self.assertEqual(test["seed"], binascii.hexlify(seed))

    # Test entropy generator and construction from entropy
    def test_entropy(self):
        for test in TEST_VECTOR_ENTROPY_BITS:
            if test["is_valid"]:
                # Test generator
                entropy = EntropyGenerator(test["bit_len"]).Generate()
                self.assertEqual(len(entropy), test["bit_len"] // 8)
                # Generate mnemonic
                mnemonic = Bip39MnemonicGenerator.FromEntropy(entropy)
                # Compute the expected mnemonic length
                mnemonic_len = (test["bit_len"] + (test["bit_len"] // 32)) // 11
                # Test generated mnemonic length
                self.assertEqual(len(mnemonic.split(" ")), mnemonic_len)
            else:
                self.assertRaises(ValueError, EntropyGenerator, test["bit_len"])
                # Build a dummy entropy with that bit length
                dummy_ent = b"\x00" * (test["bit_len"] // 8)
                # Construct from it
                self.assertRaises(ValueError, Bip39MnemonicGenerator.FromEntropy, dummy_ent)

    # Test construction from words number
    def test_from_words_num(self):
        for test in TEST_VECTOR_WORDS_NUM:
            if test["is_valid"]:
                mnemonic = Bip39MnemonicGenerator.FromWordsNumber(test["words_num"])
                self.assertEqual(len(mnemonic.split(" ")), test["words_num"])
            else:
                self.assertRaises(ValueError, Bip39MnemonicGenerator.FromWordsNumber, test["words_num"])

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECTOR_INVALID_MNEMONIC:
            self.assertFalse(Bip39MnemonicValidator(test["mnemonic"]).Validate())
            self.assertRaises(test["exception"], Bip39MnemonicValidator(test["mnemonic"]).GetEntropy)
            self.assertRaises(ValueError, Bip39SeedGenerator, test["mnemonic"])
