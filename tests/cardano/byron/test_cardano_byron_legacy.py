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

from bip_utils import Bip32PrivateKey, Bip32PublicKey, Bip32Slip10Ed25519, CardanoByronLegacy, CardanoByronLegacyBip32
from bip_utils.cardano.bip32.cardano_byron_legacy_mst_key_generator import CardanoByronLegacyMstKeyGeneratorConst


# Test vector (verified with AdaLite)
TEST_VECT = [
    {
        "seed": b"2f319d790e51c431e020dc21d09bfe7b40afa22a1b83e1eaa57cd50861bdda49",
        "hd_path_key": "b688fac5ff84e46984112e6f5e91f22c2150ece7de48c3e1f0cff25ea8d192e9",
        "master_chain_code": "93346f3f36037504c3d6072abefcddb5782a6f1dfc6aaf506c68e5182600d7b7",
        "master_pub_key": "0072629d389eabb6a4a6e35c9b0cab50b546b4a49a20d1d831956bd06098ba3370",
        "master_priv_key": "a87f10d04b34fa8d8218674532d8becd1eae86ef63e6b732a0a8c0b566bc09482259a057e2a818f0e42ce687f8af0581c95b6b12df4b1e88e684091744c9f28e",
        "addresses": [
            {
                "address": "DdzFFzCqrhsvhr2H1sncDochxM3RA3PjwacMrftSEaHmzBYNQKwBhbt6hyjfk1czqWRANSphdiirkr75t5K6mHrZX4gzTLQhQFRstheA",
                "chain_code": "08f5d795c06af01f9c7093f8787c904d25f1d549cb05306302aebed3b7a0db57",
                "priv_key": "01e6081b43f350f69d7cd455cafb92380fffcf07acdf98839161891e204dd20826a19ec325c2e87b9d2b57af40a4013a912e88dc42ab20c439b9c74e18fdb709",
            },
            {
                "address": "DdzFFzCqrhsxSGG1QAiTV1Z4F51QJcyDNCT7CTQwbfyFZ6wDgT2hTZM1MzLfuLfecXe1ExjDpabASNtEbexU1jdpg6PZaVZCT1YZwBsJ",
                "chain_code": "81376aa52eec76f35b356a43073afc3fcb5a19446e5a7128be895f6ad4d066ff",
                "priv_key": "fd750aafd9debf1514599e1170445fc53effa7a7ccb7900b31dac1ded7d4490946131c731fae463fef271b37995fe5dc53217b243b88600de71c0c5df63010f0",
            },
            {
                "address": "DdzFFzCqrhspCDxno6QVCbawGU3EuydBQDzN87rChTt4QbrKFGHNzP76bCsCGKhGamWvZn6czXSbAUqLbXBVZ6sTqSUkrfvzrv6d5paz",
                "chain_code": "ef0d1111c746cf249cb0877dadb3cfcc679f3507302e42a9f9b9ad4091774ab7",
                "priv_key": "a7cc73807915e7d64b7912c87107451e67e7cf9f4447607361218206105dba08081a5480419acdb7c0992b177200dd17181d94cfadd241898844ca2495142e11",
            },
        ],
    },
    {
        "seed": b"d43083cf2ae7e9c73246ca1bd85afe559014d2290163940919faf2c7a83cda49",
        "hd_path_key": "de7e4259e27f032efab57679eeff51f21b4880e5e6c7b97dd4bd2bfcd4d4cec1",
        "master_chain_code": "808f49bea5e22f3c1a251fd54ed9600dccf00d40cac2f294b12a04b75135e21b",
        "master_pub_key": "006f014c85ab32883492e98b764b93bef7b9f8b1e0b6424d3d5803429a9d80b347",
        "master_priv_key": "580a1a92ff3efbf74dde9b607933087096874a133199c3aa65ac3d4ed50f2f5fdaf644556784a43e4c6497a7f0ab9e5910dcd27e804b6d194912d0e05e66a557",
        "addresses": [
            {
                "address": "DdzFFzCqrhstws2ZKXmHuL8ffzhyUXLRpsxwkaXYPrivbQm2ZhZioWiACJs1d4scWESVqhqxNPP3sBEe2rBsbqcDkgZhFMSjfzcS2XwX",
                "chain_code": "6e93b93df6f40ac747251ceb72619373be6325fcc5ca983ceeb193e98f0d6ab7",
                "priv_key": "002ebf9377ddaae7560b5eda6257fa53d508832bb29a644c4edd3557ce50e80fbfd01b4957c22dfb11e1b7805129097a9dd53e81ab98ea43e35e2dd860f1e962",
            },
            {
                "address": "DdzFFzCqrhsim9Xi6EkU8qgg8bbH2kxuLorUurKUpiFq92Yd2hxpvixifSSzefpKKA4WTqBNK2j6pHzhKGU2mRkjUHyRed1v75brvZvD",
                "chain_code": "3640dcca7511ddcc8f084bae150a40669dc7cce380f1bc9e63d8ef5927bddb02",
                "priv_key": "05b1f5d00911deaf75e0b555a989c8481d38b37b12d26cdcee1d7e8e6e714008ceb60863ca6b4fa213a557aaf49a1eb2789177c195798c3a436444c70216bb17",
            },
            {
                "address": "DdzFFzCqrht2rT6HFtzMwUVqk4GUENd8L8hs9VuikTiXR8ejHWwpYpMVXfRATKAcRhaRvfg57XKUjLFMsHAZSRzhEfi49LfzLaLPTvtb",
                "chain_code": "0bd5e73da2adef5fbde9948a403a177c05bfa11b04b8196a3c1150eb4bbf7596",
                "priv_key": "7b59e92e4d5221af10268fdf44d5325f8578a3b36a120c64f6ed6d9eae29b80f1337934313bb98af5b8ca946c4e5bceaca39be43d7f7186c932d1d8894174ab9",
            },
        ],
    },
    {
        "seed": b"6e44c8da7e25f37513b01aba095ec72198e38b88dbb9219b97c856e062f6622c",
        "hd_path_key": "01790c39973b38a28eba4b7e73283355288bd9f724727ffefb8560822c3f6869",
        "master_chain_code": "b1f007dc2169e56cc871701b9eff00d2b718ea05419b1fc437b94b97ee8b0913",
        "master_pub_key": "000fb7d7210457aa248eaaed105b228b07150eec6f7c0ddb89e0f57f5e5040a854",
        "master_priv_key": "c88cd8e772af784f9d2c22edd694ef0e3cc4f9503e3b0a1a7077f8e43d12e658a2832e4e70735d1b558e6cd219940c2f26c0bc3a402bee6c2b7d552e1edfab06",
        "addresses": [
            {
                "address": "DdzFFzCqrhsxZJSHsvvFf8KzNnfZmWy33WCn8g68QJMXBzoy5kbWVC5tdnbNGSPbFpuEdsX5kAoPhYbCfqsm33KRSnm8c3jnufeP1SRF",
                "chain_code": "6b787587e41d3410621a6186177adf18d662916b52619f97ef38e55f91092402",
                "priv_key": "cd434306554962d6c47d03b2fe32e0970b053bc2fe33fbe3f0b0a186efaa970aac6f0497d612310c36b3332dc4712a0aa8b8b319501ddc2dc4bb47a9433e3e96",
            },
            {
                "address": "DdzFFzCqrht59LzwaCr9JGk7jPF8LatSb9B4ezjU7fvvN31TSu5KCZUEarnYHpHhDoJx133fjNbWjDtNCWDp8DZAc6g6q4EicsmEjEL1",
                "chain_code": "ebcc1910fd88ec111cf908dfe9be02c0f1f1ec4f584edc32a2cc95ab5293fbde",
                "priv_key": "7cd7ecbd34d2f9a62fe402534b703dae538d8a29b75cabcb980802c6cef2060ad96414d2d1eeaa58bdf92ca755afd6b64e5f80c4e2e7f7f645bf446e462ac1c5",
            },
            {
                "address": "DdzFFzCqrhsiKC8SNRZnwNtxxqhLTVBVSXcET7AKRWkVJ4qMoEkLkqQXRcvGuhi8Kbvq34kbYQ81De1qXd3xwVCP5RmN6CdvFzysQuHA",
                "chain_code": "e9d1e5c6582bdd3e4146ee3f390ddbea48019218bd38b8cd9365273a28a6efb0",
                "priv_key": "1c7f1cbe5c7a7916706caaeabaa80cfe4b5552a976f4cad3a0f049fe1e43970a9eca831627174e9fc7eaa14e278d1386ac1266f9f6e99e29622997ba3ee02c1e",
            },
        ],
    },
]

# Generic seeds for testing
TEST_SEED_1 = b"\x00" * CardanoByronLegacyMstKeyGeneratorConst.SEED_BYTE_LEN
TEST_SEED_2 = b"\x01" * CardanoByronLegacyMstKeyGeneratorConst.SEED_BYTE_LEN


#
# Tests
#
class CardanoByronLegacyTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            seed_bytes = binascii.unhexlify(test["seed"])
            # Test both FromSeed and direct construction
            self.__test_wallet(CardanoByronLegacy.FromSeed(seed_bytes), test)
            self.__test_wallet(CardanoByronLegacy(CardanoByronLegacyBip32.FromSeed(seed_bytes)), test)

    # Test invalid HD path decryption
    def test_invalid_hd_path_decrypt(self):
        byron_legacy = CardanoByronLegacy.FromSeed(TEST_SEED_1)
        addr_err = CardanoByronLegacy.FromSeed(TEST_SEED_2).GetAddress(0, 0)
        self.assertRaises(ValueError, byron_legacy.HdPathFromAddress, addr_err)

    # Test invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, CardanoByronLegacy, Bip32Slip10Ed25519.FromSeed(TEST_SEED_1))
        # Not a master key
        self.assertRaises(ValueError, CardanoByronLegacy, CardanoByronLegacyBip32.FromSeed(TEST_SEED_1).DerivePath("m/0"))

    # Test wallet
    def __test_wallet(self, byron_legacy, test):
        self.assertTrue(isinstance(byron_legacy.Bip32Object(), CardanoByronLegacyBip32))
        self.assertTrue(isinstance(byron_legacy.MasterPublicKey(), Bip32PublicKey))
        self.assertTrue(isinstance(byron_legacy.MasterPrivateKey(), Bip32PrivateKey))

        self.assertEqual(test["master_chain_code"], byron_legacy.MasterPublicKey().Data().ChainCode().ToHex())
        self.assertEqual(test["master_pub_key"], byron_legacy.MasterPublicKey().RawUncompressed().ToHex())
        self.assertEqual(test["master_priv_key"], byron_legacy.MasterPrivateKey().Raw().ToHex())

        for i, test_addr in enumerate(test["addresses"]):
            self.assertTrue(isinstance(byron_legacy.GetPublicKey(0, i), Bip32PublicKey))
            self.assertTrue(isinstance(byron_legacy.GetPrivateKey(0, i), Bip32PrivateKey))

            self.assertEqual(test_addr["address"], byron_legacy.GetAddress(0, i))
            self.assertEqual(test_addr["chain_code"], byron_legacy.GetPrivateKey(0, i).Data().ChainCode().ToHex())
            self.assertEqual(test_addr["priv_key"], byron_legacy.GetPrivateKey(0, i).Raw().ToHex())
            self.assertEqual(f"m/0'/{i}'", byron_legacy.HdPathFromAddress(byron_legacy.GetAddress(0, i)).ToStr())
