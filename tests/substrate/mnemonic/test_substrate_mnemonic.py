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

from bip_utils import SubstrateBip39SeedGenerator


# Tests for substrate variant
# https://github.com/paritytech/substrate-bip39/blob/master/src/lib.rs
TEST_VECT = [
    #
    # Basic 12-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed": b"44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453",
    },
    {
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "seed": b"4313249608fe8ac10fd5886c92c4579007272cb77c21551ee5b8d60b780416850f1e26c1f4b8d88ece681cb058ab66d6182bc2ce5a03181f7b74c27576b5c8bf",
    },
    {
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "seed": b"27f3eb595928c60d5bc91a4d747da40ed236328183046892ed6cd5aa9ae38122acd1183adf09a89839acb1e6eaa7fb563cc958a3f9161248d5a036e0d0af533d",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "seed": b"227d6256fd4f9ccaf06c45eaa4b2345969640462bbb00c5f51f43cb43418c7a753265f9b1e0c0822c155a9cabc769413ecc14553e135fe140fc50b6722c6b9df",
    },

    #
    # Basic 18-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "seed": b"44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453",
    },
    {
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "seed": b"cb1d50e14101024a88905a098feb1553d4306d072d7460e167a60ccb3439a6817a0afc59060f45d999ddebc05308714733c9e1e84f30feccddd4ad6f95c8a445",
    },
    {
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "seed": b"9ddecf32ce6bee77f867f3c4bb842d1f0151826a145cb4489598fe71ac29e3551b724f01052d1bc3f6d9514d6df6aa6d0291cfdf997a5afdb7b6a614c88ab36a",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "seed": b"8971cb290e7117c64b63379c97ed3b5c6da488841bd9f95cdc2a5651ac89571e2c64d391d46e2475e8b043911885457cd23e99a28b5a18535fe53294dc8e1693",
    },

    #
    # Basic 24-words
    #
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "seed": b"44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453",
    },
    {
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "seed": b"3037276a5d05fcd7edf51869eb841bdde27c574dae01ac8cfb1ea476f6bea6ef57ab9afe14aea1df8a48f97ae25b37d7c8326e49289efb25af92ba5a25d09ed3",
    },
    {
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "seed": b"2c9c6144a06ae5a855453d98c3dea470e2a8ffb78179c2e9eb15208ccca7d831c97ddafe844ab933131e6eb895f675ede2f4e39837bb5769d4e2bc11df58ac42",
    },
    {
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "seed": b"047e89ef7739cbfe30da0ad32eb1720d8f62441dd4f139b981b8e2d0bd412ed4eb14b89b5098c49db2301d4e7df4e89c21e53f345138e56a5e7d63fae21c5939",
    },

    #
    # Various
    #
    {
        "mnemonic": "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "seed": b"f4956be6960bc145cdab782e649a5056598fd07cd3f32ceb73421c3da27833241324dc2c8b0a4d847eee457e6d4c5429f5e625ece22abaa6a976e82f1ec5531d",
    },
    {
        "mnemonic": "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "seed": b"fbcc5229ade0c0ff018cb7a329c5459f91876e4dde2a97ddf03c832eab7f26124366a543f1485479c31a9db0d421bda82d7e1fe562e57f3533cb1733b001d84d",
    },
    {
        "mnemonic": "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "seed": b"7c60c555126c297deddddd59f8cdcdc9e3608944455824dd604897984b5cc369cad749803bb36eb8b786b570c9cdc8db275dbe841486676a6adf389f3be3f076",
    },

    {
        "mnemonic": "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "seed": b"c12157bf2506526c4bd1b79a056453b071361538e9e2c19c28ba2cfa39b5f23034b974e0164a1e8acd30f5b4c4de7d424fdb52c0116bfc6a965ba8205e6cc121",
    },
    {
        "mnemonic": "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "seed": b"23766723e970e6b79dec4d5e4fdd627fd27d1ee026eb898feb9f653af01ad22080c6f306d1061656d01c4fe9a14c05f991d2c7d8af8730780de4f94cd99bd819",
    },
    {
        "mnemonic": "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "seed": b"f4c83c86617cb014d35cd87d38b5ef1c5d5c3d58a73ab779114438a7b358f457e0462c92bddab5a406fe0e6b97c71905cf19f925f356bc673ceb0e49792f4340",
    },

    {
        "mnemonic": "cat swing flag economy stadium alone churn speed unique patch report train",
        "seed": b"719d4d4de0638a1705bf5237262458983da76933e718b2d64eb592c470f3c5d222e345cc795337bb3da393b94375ff4a56cfcd68d5ea25b577ee9384d35f4246",
    },
    {
        "mnemonic": "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "seed": b"7ae1291db32d16457c248567f2b101e62c5549d2a64cd2b7605d503ec876d58707a8d663641e99663bc4f6cc9746f4852e75e7e54de5bc1bd3c299c9a113409e",
    },
    {
        "mnemonic": "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "seed": b"a911a5f4db0940b17ecb79c4dcf9392bf47dd18acaebdd4ef48799909ebb49672947cc15f4ef7e8ef47103a1a91a6732b821bda2c667e5b1d491c54788c69391",
    },

    {
        "mnemonic": "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "seed": b"4e2314ca7d9eebac6fe5a05a5a8d3546bc891785414d82207ac987926380411e559c885190d641ff7e686ace8c57db6f6e4333c1081e3d88d7141a74cf339c8f",
    },
    {
        "mnemonic": "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "seed": b"7a83851102849edc5d2a3ca9d8044d0d4f00e5c4a292753ed3952e40808593251b0af1dd3c9ed9932d46e8608eb0b928216a6160bd4fc775a6e6fbd493d7c6b2",
    },
    {
        "mnemonic": "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "seed": b"938ba18c3f521f19bd4a399c8425b02c716844325b1a65106b9d1593fbafe5e0b85448f523f91c48e331995ff24ae406757cff47d11f240847352b348ff436ed",
    },
]

# Tests substrate passphrase
TEST_PASSPHRASE = "Substrate"


#
# Tests
#
class SubstrateMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            seed = SubstrateBip39SeedGenerator(test["mnemonic"]).Generate(TEST_PASSPHRASE)
            self.assertEqual(test["seed"], binascii.hexlify(seed))

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, SubstrateBip39SeedGenerator, "", 0)
