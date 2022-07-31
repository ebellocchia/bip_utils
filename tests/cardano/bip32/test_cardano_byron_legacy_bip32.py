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
import unittest
from bip_utils import Bip32KeyIndex, CardanoByronLegacyBip32, EllipticCurveTypes
from tests.bip.bip32.test_bip32_base import Bip32BaseTestHelper
from tests.bip.bip32.test_bip32_ed25519_kholaw import TEST_VECT_EX_KEY_ERR

# Test vector
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFBSLcEQ6gUqC8LX7zrf7CYLJ8G5mvoUVVX6DY8GYJVjQ3oo9nVNSqQxVBbJL8BsAQNMhMj93bCutYE7WQr37ERjuj8gHGR9",
            "ex_priv": "Har3K3MhV5fiuEp6zgdjmzbVnfzYPDmft6xGLtSY8CENfu8vjggiicssgA569SGDF1hhhp2Vs6UHhrHu3w96GsTQmCSzfeRuDZT5xpmS93yYsYNkbxjCBJMHUPrPWoAcm88W5DnUDpamzqLKXtKU82n2rZ2",
            "pub_key": "00388a13ae11fcf6e8f33fcf3880413471e19876501c4f5efc5edd10bc647916ca",
            "priv_key": "08e7254e51724a3e7e33b951f74dfda4d93095fcb08be7527ac63a17ea7d115870cb138e77393957b88ac55c4d70d7d06f132b35ba664cfda42b73ad4af7850a",
            "chain_code": "4014b221c34312b4896767c9940463dee132307436249318d87c685c42e4cc3c",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub68CUUpLCv1ej8PFPbc6u3GDHNq7PwNYpVGEZMfYJe93tn4GAmLbA3ozr64PETQU7Hc2Uu9R2yBbWu94yrPP9gHXszAswu5wunscccMmFhxe",
                "ex_priv": "Har3K41TaS8ywaUzpEE4ArUyfH26zeNMYUsiPrVX7KRFbtyehiEimrgi8oNZAVnyZHDp3X42oayLg4pDDpu9urWKD5SctZW5Ce1ZiTkFMAPX3kPvo2zeBvww6ecwjvePi9SCEciHtJcZBX1v2JeGzU5wuR6",
                "pub_key": "003ae944aa0e3d2aa74f4fdf1b2f818244f7809a9c8583090e46a595e64d06224b",
                "priv_key": "4f7c912da6a30e3e674b8bbb2e95d27cf9c075cdb94bd8732a67f39ffa05f2081b6cffecbcf999bb60318ca9f0b26c834fc5d70d421d7f1ac3fd3814bc916fde",
                "chain_code": "444cc1e24a871a55f38958ddf4644407683ca54c3ee7f06be4b218ecd6e88ff7",
                "parent_fprint": "2a2b0a59",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6AMMsa8s2L5P6X9yuVysAcFyu28Ju53XTxjBWw92GedSXCxZ2L7JjVyhUPvpoR4PyGASjYMhGLHQygHMiNYyTtWtQkT34acTTDCLpza4FKb",
                "ex_priv": "Har3K4eZKBK8j3qmYJwqyEiT5qRncigydZ3FiQJcndVR24PXRPkhF9gbaC42iB7gkCZAVu3x7attX8Mwp31J7vQng7UvyyM7UCCMEb2NxqY2GMuQ3CtAqVZhEHumUoQstDUqGeQa7d35ghJxS4ogoYP3zgJ",
                "pub_key": "0008d814651c10a30068c0f7d70a09106dbd12f9c16ad7324995a775833b0fa64f",
                "priv_key": "6c89e90236de6e9693113617c9e8114bb1992eb67254b8c45a87435873feda015188868884dc672a16f147a2313d0805c415ede5ccf353c8e9e3151a273b1be3",
                "chain_code": "75ac4748b21931463935c7d19dc5a38ff16f0776e6ab957e1146d0f4d7960d7e",
                "parent_fprint": "4f1d4987",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6DC6DhwRrhZcYs3eFNVLCrmWGcvmvUojf7pdAQ3GF1LLCS9EGF3Q5KfHvRrUZSJuPHvnyGUywEEhLcKKg3BzVtKDNayqnKpJhnmYAdvQud3",
                "ex_priv": "Har3K5VVYkJstGdpvQkmS5SuqbFwMcUxrhKxCko5rgWmP36vturBGAaZ1HZcdvZQ1hgqd9V2YUoZGGnE1RmGXDRR1b1te9EJqAEStAKKS3bdmk3NwePmtwnCrq3LRS63DDe53tduAzrvPARA92zy2uuy5ee",
                "pub_key": "00aed5d2bb585f7c5d4facb8c49f77d53954d6dbc606b80ed218abf4cb099a0dd8",
                "priv_key": "cc1942bbce0eafa6ebd15e57597932a339dae6c6ca54c0e4baaf1b8163af6b023cd5fb8d671843888ccd45ae969fd3717efecede109e21b5ed273fc0ff640f5d",
                "chain_code": "fbac2c1c29ecfe4a04537ddf0e73f1269c119167c7d76db682eed40486bee848",
                "parent_fprint": "d185ef94",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6DrdzEdjZyCXd9dnieEwiSVDsLxZCa7M6BeVAhadASFC4sNWz7VRypL4A1xBeLdmbqMmxvfbZVvdC8LpqyjvP6rdNwGbJRe1T1VwNBpu9T4",
                "ex_priv": "Har3K5gwi8S2W5btF4FL1t13A31SdJCcM2GvqDvLi11A9qe296nBmfvEvTMNMciSSTwtu2eddBtDs8NVKgiLW9s5NpR75R8mw5L8zHwHANjusak3BUNcsN9pxnvcxQfutEDZUsvWWrNY4mBppoMpVAfv1GJ",
                "pub_key": "00dfb8cebc7907662fcb1b838936da389aeaf667b7f0844494404b094ae5216dde",
                "priv_key": "663bd9f51db4a5def2b62caecc973997e07a47076395b085db0734990b781c0bfea0574575e1ea10b0634a6bab1db0aaa112a5883594ded93d5ccbfde7f37dc7",
                "chain_code": "392d79d09e50473335ad1f4d0caa5421203c800a8a4087a6a392bad812510c87",
                "parent_fprint": "2bf1e400",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6FovDgfLr8TWPJhpJvKaLqDXntMJkaHLr3bbqXd58VhhtzeyPs1o9mXosYVBNQ7qiFDyu5RaRRc9zCdn1SnAKjDqZiDhdU1keaRqq58JU5R",
                "ex_priv": "Har3K6GbUb6cLtTXe6riD8ATnfuEF82zUGF7LbcCJbZxjkVzkznoATNjQ2FmiwmTSdVYV6sWYrgSWacHs9QrPsf5UP3PA3R2KvXaKNBBWfNH92Z6vMLDu21Q8KFxfxDkXCGNvViwSXu3MYk32TE2XacKD8t",
                "pub_key": "00dab56466c9b78c9b3d2e47bb406d33191a7ee71b72288c0566af973289b27f30",
                "priv_key": "10dc9e80a859d8bea52ab77c6d6df84ad83378a75b4601468c8874b133d8f403b8213e13ed6a5d6af8ee2c5fff23d252f0d11a32b5b7469b855e3a233f67abc8",
                "chain_code": "fbcf5180f7cbac1781b9efde5d5fafb0d8ec98cf0400d5f499bc7fa17f7f6f1e",
                "parent_fprint": "35aa9736",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcGhjpsX7ARdNiRcTzUZCTbRULpVaUXrvPuHpVub3mxSLh5RHQQpW3uwudbofh6KtyF5r12xB6qNj4cbnSzniLyJkz8yr7pTX",
            "ex_priv": "Har3K3MhV5fiuEp718s8wxrMQCSAkYTaQRXiAGBUtttX5UcTVoVatc8AgR7FymC2gHcqrV1hq3o2rvJJWEZ4cvyiJu3cvUC7X3am3nffYpSGH8wjoZRN3GyxwQF9q1cMgqMq3xSPobedmuTfpca9Uhr1Xea",
            "pub_key": "0078b30c17d78b40b88004ce5931fb980e96627f603bc901ad4534c523791fac20",
            "priv_key": "70c50ef1e05e362f4b3ad835b06958e89928620b1c8f222a740cde54cf1c174a40b27bb712ad85478719080b99fa428f58a4cd4f38f62092af98e8b802f1aa1d",
            "chain_code": "d8ff46bf9636d2e9d7e6fc2f346d703aecc2165a2be4fc2f0971bb2859b05ff2",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub69dY1igMTEAFbMHUbXo1UAXe3mN7c3aZX3hC2pYUL8pXGTKshZpurLweHR5msQDYLH5xEqRBZAUVanNapYLmDnotNt2iT9umQX9qh8su2Cn",
                "ex_priv": "Har3K4S8gbHicwnVwrCx7zCCVNbmwiJTukEwd88FxZvCaqmSW6F78HexwvL8P2bVaXzXsDY1b6UK4ipBkmt5ufP3nXJw97fgSgKK91uUFgms6EgV19GtYAiKGs7Exrb8qTfqkayZT5xHpNpXGNujyRhCgoF",
                "pub_key": "0056b85695d3de110162df2114063b19433b1cc68ce65e1286a04663127f2ddcbb",
                "priv_key": "ba4e342423a5906ffd15a35c39cf7e33da904224ec0f032bf43c9e1de8dcdf0a878fc700ea5aa3d1680c111767b144ebd25cbed9d53dc98ca5939a2bb6038164",
                "chain_code": "3ed94f8bb446ffe808b852feafdf9d156a729907db7b62c25b36ce21d818407a",
                "parent_fprint": "ed01390b",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6BCYprAX7nMJ9cBxtzuJUG65caBTdXHw4wrYaq2XcPL6SNgrQ9ga5wBCZChkSqUZFTkVsKEpmbHvvWv4kAGo3dsosSNHVqySrPj7E9PbMnF",
                "ex_priv": "Har3K4uApR2kLfSVkrpRXspLqXQkvxrF9jGb5yYseFve4PVaMjNLPshH4YkbZy2mxXTP1gtzvrdfGbY5avgi9nBdY6FXHFbotCdW71FhBwDGpSVz3vDzhx5cfr9tJjDkqECSB66GMimrcG6oC27huGEnfHb",
                "pub_key": "004b501327c18b38710f0d08b5fbd941a5caefe21e428c0442960c315a700cbbc8",
                "priv_key": "ff0b25ca17cf4d1fd71549b0ee9bf67211710395c4b8db3b1cd58676c09de802e535c3373c552f5efc9b0152413fa7b6683af169540dbbc690d7dd28793f6dc0",
                "chain_code": "1b5f2f57da0c253f1cf3c46a6d4acc9737c2e3e57866d7f47e2218a076cc5417",
                "parent_fprint": "c27f4065",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6DD6dfFKeMvfvFByDSh2hiCsTJzem9DwwHDi52nGSB2mdtxRcidJdeYR7UG4pdPpiA345Fu3ctRShaLuEtaPBB2PpauhBbevoU8Rfo1wQ43",
                "ex_priv": "Har3K5VnuBPbuUrsNXJVsmCw7afYpDB9fGfg9ecAgMWvNwkWmDRR7gMZTtnNbBAywg98ttYU5QXmSj9NpSXk74dnykMM2MFYrvW9AX2FqghxBnb5qNwxoga1zGfoJuTfUMSvPxARecSk9WXoWa7L6YFsndL",
                "pub_key": "00d37511919ffb330efef3baf36844d789c5070e88f080da038d51211ab7305d74",
                "priv_key": "8029d56376fd0b97591996d085f7613d71f9d3bd1421ecc3e495df5611dea00b04d55d202e1321e425a8006d0bcded43e78db9deec849578791e5edb5a206ba4",
                "chain_code": "e976e56b26fbff1fcac93351288a481c345c678124cca27555bb738ce0ceb02a",
                "parent_fprint": "d3e2b68a",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6Es6aGD81TheeJamsXcFLaVHH1hdFpUnNk7q9anpaTq332CMM9H5Di4uYX98ZdsQcP3fzN5hthGbH9qPNSMopzgHEdRE4qbAxfmmxKjtNBC",
                "ex_priv": "Har3K5zJvaSNKWfQbjCGCEY3xVaUkjZSFPW4tc56DU3E8rRXCMsVwy4Qz4FL7NMveHkNRKed9nsProGa3dEBodwBwL7pwtrgmT6JGe8winR5w7z2QZBpPdrtjbknyTgfLkkPU8LbPkNKRDFxaBtDJNcvqWU",
                "pub_key": "00a1cc378aea4c02bdf41a12edcd74a4273a061c0fe6c31d5f1ac702a55e7faba1",
                "priv_key": "8916e4a59fd4dc46dfa247e801526ddff9c1340ead1985fca456704fb266410c05db1ca2d300238dd426f134fb92ff8abb3865aa06d9fe7ef6dc6699107909ed",
                "chain_code": "9b2f789d57b4f07ca163f76951bce115e0594889d03f71ed4b67b6bf260fec3c",
                "parent_fprint": "b5123a91",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6H9AXt8sxQXVRwCr5UL2VedWQ79VWSdB3VNMe2FhBAzC3qeBKbBfBbXuSo7JNsC7HkGT3q8r3gZvTczTfEoxzjs3FjBth3tHEbueWpwEArE",
                "ex_priv": "Har3K6fYQbcRdMov4uaUzEQsArxDMv6Ptppn4NA8SBU1UwtwzCKo1gP5JdKUUXxq2wyZHq4k2jwDLiFXmHc5fR6XsKia23e2snk5gx74C9QcQNCn9emXvKQX5VEsFi5AyX2bC3Q8v5u9e5JJNk3pWnCmA7t",
                "pub_key": "006b70d0e5cb3dd1e1f84d1c2e6b92d9a5d6541e45379ee15745c1a0b95eba506f",
                "priv_key": "3e0c1db4ecee61a620439e5ccef64c4751e2fc7ea5824d5d5d47810f03ef2905113138e830aae0a83742e3d018ca964203165218a00dc73fa978e37b047d9409",
                "chain_code": "75f3c3d37d8e7328c101a5fe4aee92023b5a11d9b9d8644923a821abfba0edf1",
                "parent_fprint": "eadd62be",
            },
        ],
    },
]

# Tests for public derivation from extended key
TEST_VECT_PUBLIC_DER_EX_KEY = {
    "ex_pub": "xpub661MyMwAqRbcFkJT4ooNX5cdbj7LrcXKzMeebV2T3RvtDMKRhYKuFbGnidP9thFCKmuTe58Pa3uTGiwqU1UedwDrEeXLpMNukEnfN9GudgR",
    "ex_priv": "Har3K3MhV5fiuEp6zrPyJxoWLVRQZ5chetTUpEAse5LQz4LFtDkQCpDwGpFH6jK1yAiTZqVxhay7EKh8JNY9Dk7FBrXBkt7PV8yiVqXQqD7hWwd9iuZwVquxNyH8tryWvv5kmMHdd1LFMsqSK3KPSX5uFsq",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "ex_pub": "xpub69Dx86u91nSZVTDAp7WpMLMB8oWBttyTVKdfGRvt8jVXtU4YbK8zRgJtocZHguQyEy5uPEPmcjkWiYDvgZ9GGz3DtrxfbAsdgyApo2xgpyW",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6ArKXbqLEt52HDd6djBvX2XBmnyBYZhNZKo22aXLDhgy5jkPDmMDQ4ncijrfaMRQxUwZZPhyMv9Gr8TAp1A34CFm67hc6LZxZKu3r1G87vG",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Tests for public derivation from public key
TEST_VECT_PUBLIC_DER_PUB_KEY = {
    "pub_key": "00b83340567ccea3de6c12c76fb2574bd68ecd8560f825632a0fb066ec149fe7e3",
    "priv_key": "141cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4052ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "pub_key": "0031b08a58fba8781fa3d4197160790329232980b9eef56568251e89f5eba211f5",
        },
        # m/0/0
        {
            "index": 0,
            "pub_key": "002c9316c129b5f5af551e6d2defe556efcbdaf8407d365c0634dad7384be9535d",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}


#
# Tests
#
class CardanoByronLegacyBip32Tests(unittest.TestCase):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(CardanoByronLegacyBip32.IsPrivateUnhardenedDerivationSupported())
        self.assertTrue(CardanoByronLegacyBip32.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        Bip32BaseTestHelper.test_from_seed_with_child_key(self, CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        Bip32BaseTestHelper.test_from_seed_with_derive_path(self, CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        Bip32BaseTestHelper.test_from_seed_and_path(self, CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        Bip32BaseTestHelper.test_from_ex_key(self, CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        Bip32BaseTestHelper.test_from_priv_key(self, CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        Bip32BaseTestHelper.test_from_pub_key(self, CardanoByronLegacyBip32, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        Bip32BaseTestHelper.test_public_derivation_ex_key(self, CardanoByronLegacyBip32, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        Bip32BaseTestHelper.test_public_derivation_pub_key(self, CardanoByronLegacyBip32, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        Bip32BaseTestHelper.test_invalid_ex_key(self, CardanoByronLegacyBip32, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        Bip32BaseTestHelper.test_invalid_seed(self, CardanoByronLegacyBip32)
