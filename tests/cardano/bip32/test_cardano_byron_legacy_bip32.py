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
from bip_utils import Bip32KeyIndex, CardanoByronLegacyBip32, EllipticCurveTypes
from bip_utils.cardano.bip32.cardano_byron_legacy_mst_key_generator import CardanoByronLegacyMstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import Bip32BaseTests
from tests.bip.bip32.test_bip32_ed25519_kholaw import TEST_VECT_EX_KEY_ERR


# Test vector
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcF7662zBJ1fFDVzNJxryvA39ZHKqEGXDpEpAnwW8f2nbwnVw2v3ufugPrfLi6RzUu1toysEQD6zQKsW357o7hPWoKFnEQyXf",
            "ex_priv": "xprv3QESAWYc9vDdZS7rS4mqdKzAEvUU3cYHZ5SBVsHgiEX6kR3WKDKL8tJjxcmWttUMR414UShfQvun9QpmVGhkHXNe5svUcaPqMe47UowvLvEMU9Y1k91rUtHDEDpAdGnmbmupd7K3TwGMrKPheyVhPDZ",
            "pub_key": "00f0e072559de7502b3e9f782494fca435d22bf1b6f3e4e2b2bc43dc008f02c0ab",
            "priv_key": "685d8225d13a53ad5a79843baf8dc1c03fe73d8ffa9b40b44a5cc74b89783d47a46aa67f1b7d0fb61ba122d0b9c1c0c666eb8e6b1744af7035ee21d482ca9a3f",
            "chain_code": "388c96cc80b58a3e4ebb89b68bd3a96eaa5b162993faa5e91dae31d060616d0c",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub68mwVMQHvH7Fu1jr3CRugYktF8Lp9gWWgbsVAJxuHgXUhLhXQrLBWtgDTBjZPYbVWDXwsGyhaCtA9y1hH3Ai5PDhreSBFjTb2jX49f7Z735",
                "ex_priv": "xprv3R48rg2arM2YB6ZppjrF3GUhpT8J1ztzRvrY7YMJYsWXo9f2KQRSjy2bF2FGd9yhDVirCx5jVccjtupUb2g3SyXNg2ip1VfXxcnYHEkvTBPvcWY4dp6uxsAG5xFU9jWSysANzGJRejFiSSQuiWPFwzf",
                "pub_key": "00df3d2b0405ee04495f352bd4b93ef686452c8439c95155f0699db0a2e864c123",
                "priv_key": "8886bc26df5a4845105bb03c1a1f22aadf8fc6cf2ad4e874f3e4afec51598e0f2642bc5df496c0b4dc023a96f86d485f9f0fb0c04d03160c51c43d36348afabc",
                "chain_code": "abf36c1f4f2b65ac4cb69d044cef88c84ce03143de444ba097e7413948b972bd",
                "parent_fprint": "78ab38c4",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6AjnugoMPCxmrBwFRYFXdoHZ1TjPsXvjV3BGNUH7VFvWTrwW8YzoVbksRymKWyCuBg8XMJ9h45g9PcaPZe4kodSgVe17JufNBEGcSx1WKMH",
                "ex_priv": "xprv3RdxUwheXsTKHxd7XDGqA1EFxY6fyYqNo5FDbPQDgh8LwZXEEsg3qPcYVqYQBfx6T638P7G13Zb1tKxg2zRD3m7LJZ1L615nAPAFY4G2Z2oucS3GmrWZ23Hq5upNC8KxNzcNodJeS9KRV8oh8Hm2Qpc",
                "pub_key": "004dd33848db140cd5b6804d99530b5f63871db878c8de3117b3c0415ebf891571",
                "priv_key": "136ce88a8aefb284f7df6b9ab6fe1b0f2ff04e60b33c9985dbad983d0ae2c60f37616616374527ed555247424350dce45e3d5c4b08fa6a044beb1e6c87d08fbd",
                "chain_code": "4c85d93f7d1b0dc5d0d8e839c924302443834fd082b0419358bc7dcf371f375f",
                "parent_fprint": "83bb878d",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6CbQ2uRqrxx7yU2dxQ4bLRmYc3LtSKfdF1Jc3DkQ7aVzUm92b1E9P9LFetR2wrSynX7AKjYo1vWSPs7VjrxP6fPteiT9dEYybsffA1cCNS4",
                "ex_priv": "xprv3SBvV1oYRuuhLZeZP2iindL76iGpotmvrPSaK6Mh1wkcrRfW5rFqggHV9ZQmQeKXAY5cV6vkAYUU8WVSRtDc4FqHCi1Fg392t2f7proYaGVpoVnQvRSqxm1ZAw1ZAWHJtjSrV72f8k5bpRKBGSxhyTn",
                "pub_key": "0021517957255bade4351ba26da75f1ce91f9c0d95cfb677c3ed5c6c151266e264",
                "priv_key": "1ba522ecc726d0d4fc512f0b4aa0dc1057785f8843e5a18d4bee3886e2f20608c0c9b9ce8a7032953ed6e8af877035e5a4972100e86c196f2ebfa750d3025a8e",
                "chain_code": "9e7587a66f6ad19dfb2f7ec04c12433c7e89055d98853fe2db257c658bfad3a5",
                "parent_fprint": "8024d357",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6ESiMS858DjajW9uTu1jqQXhWY9uSNA2rZk78FrNoJKfM5hcgvJHSsH6ArGkNbtL2GSuBY4XUywqzcu4GBiDzAhPggvS2fZzE4UQ2MVnXny",
                "ex_priv": "xprv3SjoVYQs4nVnJs1WiP6edPCknuU1SQYWyJtim8WXZXjifT818bGVpHm1NuqKBiyaWALQ1Q7UUaKkJorgVnfUTeZtzvwKBpG9LW64ny9wHNfow88eq8bguZ4dhU2T3QBkmcitKkPqAzWQPMsPbgn1tJS",
                "pub_key": "003845186af158ed520c6ba91fff40a8ccfa5444583b63427285bbe8922938a205",
                "priv_key": "618e986ab88078847d32131e506e7fe0bec80f0954ed6156ec4ed9f6c2f3ce003eef66d19ba7cc368666ab175b3af485666eba5e0b0c8bbe0c50266db6e68ca1",
                "chain_code": "4703397680d94c20c1d12dadd5c6a6a47ecb21011c9ed483ce96e344e9393534",
                "parent_fprint": "7be021be",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6Gu7XBGrtQ2LZRTGw3Ehd2Qg32GTQVe39xeoSPcnFwtg1UGRuAzQgKMcgmEo32tzmLFrh2MhciDPKFMT8fuvGMSDXYarc4cChfqbaNHdM1K",
                "ex_priv": "xprv3TU6yhDCt4nroq8FdnwGM23tFhBxAKof7dAEM9TqzxucuTqqrytf3TBK3CHSvRigDNtWckQWrLmwqkGNjt55RKRexKAfk4P5fCcLhqLu7cJWGHTrP5xmxFTz79xztXjqDUYWAzGr7ERD16XkPaTGbDA",
                "pub_key": "003cdae14ef5c65a8a46475e4cf0cd8f0868968bb67328c1df77e541788468cb42",
                "priv_key": "fc8304861b0d4b7c24b7f64bedfd78bd769100d26c851ac7d42f6247fbfb3609ebc75df8a6a20764ce2b9ecde85cfba4412d0098aecc457d3dc55c64e592de8b",
                "chain_code": "a02966510f137dd2c31e83894c25e7cd507efadc5fbee664b3b2c0963b378a04",
                "parent_fprint": "c9e72e85",
            },
        ],
    },
    {
        # Seed length shall be 32-byte
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcGeU3T2YJb7E7tDptDraiMjpgoBtxo4UUuKUgq9sNda9MZ2idH9iHDnqKJFiUYf8iD7mgwd4AVcESukepkN3xyvgLK7k7vEp",
            "ex_priv": "xprv3QESAWYc9vDdZtfouUN9v8bAZMxxSoAYD5KMhrFen7hg4tFWLDeypfHZiGHVG8UeavtfRNCPofzqZNYeFb5ej3redvGbtVjUZ4Y73NDvBamyS8SERgsJvDSW4fv5shW9VYAn1sMQfFTFDpBLbENUCYu",
            "pub_key": "0039cf6dcd2b7dff3f1d877b94f059bf27b24760b767dc74e0fb9de87dfa5a145e",
            "priv_key": "20013703ad81bfd638777e54e0b676e296a736ca32632ee72c79e6d0746e8b49072e60a45882b849a398918e61fd0ac9517c484ef350ed850357cd11f973834e",
            "chain_code": "d354a691f4c4e613b4d1c0094181300c06be3f21419cda459d59f20b915593aa",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub68dHnw3XNYb6XuSVgeUhPMRr8ZJD6ykFeyGHiMch8LHyN2nzZpDrHV8zLFekw2SbDV8v6aaRXbA5KEgnF4PPaYk2VH528jZKzWoANCRdJea",
                "ex_priv": "xprv3R1ZpdvYvXrLJmA5p9uAfvT8AdEJCjNJvHBpD1VkbbNbgnyyELE6K7edP3xHrd6MWM63qsghpPgkvmLxfJJjbB4rP8bffrCnSfxKb2z4n9APgtRP4cck1Hynjzdnz3x54FbNM3CqyZDvyjZ8D2G9MrS",
                "pub_key": "00c68d05f8b9ec4c3ab6b246c1fb4421ba987d7c821e71b93001ea34ac67ab15f1",
                "priv_key": "28bac04bbae17c4e26f921addbd80f14e7e7e65a0b2c6fcf3d19e7187586530a4f81707a0cbddf98cd79e48e4b1ea30732b63040571bf1d3919eed0c0d7516f2",
                "chain_code": "966e36739c502250d5795fb2d670a1a550d7fbaf61b35ee11ac317044093db05",
                "parent_fprint": "6460eafa",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6BWRy5gjpPd8u1cPNXcuciBKKqrVZ5nKUS9hDvt1nVHpbwEHuoqWaHqcrndW1ZmBtQHSYD7YUR39tte4sXib4v1jz8UZm4hPsjBQDNBmKAN",
                "ex_priv": "xprv3RsDbPDU4Tj8eEVxWfZBkpJnsuTf2YEVnV2CDckKDJvgZUNUSWwCo1yyaAvwQ1vhsJWMudchVKuHHfdJaTBN21dHSY59p19FoPENht1Cv4GvVhLcAU5H3DiyxJEDVTepTumGiJrVvG4jgs5y5Zz2RjJ",
                "pub_key": "008c04ecd7800b0fdebefac8861e7584409b80639a07ddefe6104d8ab17c8ec3a9",
                "priv_key": "de93be12f3fa75e6dee80d98e9ee2ab4f6cf27b39b343fc0b6312fd11d57bc0a3895d40a506c926e104eb82e8e22f78b57ef98408269747e86000d221663de5a",
                "chain_code": "6ac16e1f346c2f7edc1efed1945120d68fac3f5503767396e8833732c147b210",
                "parent_fprint": "ec714514",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6C6KCucHMBBAhS4DZV6ccbPmoLcChweimNzJad6g5nzEmBANDA6asGSnMUBEwcbLsAYLJYzpW9cnCCRCMSz4yinvxaRg8REckpQn9FU6Qnw",
                "ex_priv": "xprv3S3HPepZeRKvGWVWMNH5eTTMGyaqZg4tW6PJ8UWpzohxLu9W1d1VDGaPB3AgBFXkTMkPdfUL1VmnKBBHvKxXypqfAVMHbRuv6PssHwJqxYbHKE9UF2QLchV2QYgAjLP8xPnhu2v5jHY1rW7aTG4eSmh",
                "pub_key": "00a3f5813c43f2b4e579fab2a1503b4a36c11c1e58c5f793c36d5fb26a4ca4be0d",
                "priv_key": "64549bd9966d390f1b705f2a3d9bb5e2ce48403bb47c9f602faa9761ee67bc0a0b81f2aadf01880af494a7745acb6d10b66737f383a14dce0e4f9f1ed49f6bda",
                "chain_code": "57a2ad3eaa54f4ae4bfce085b909a76eee8763cbce2932566897430bc1223910",
                "parent_fprint": "3bec4e93",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6FLWyJ3rzSkEibNGbt5UQn3mPeypQM2gEvzvTiURPdodQUEbewweawDo6Ai1crtUqKhjMe7ZSKvW1LCQ55pSmHuN2iwRgf36aSEa6KLwufC",
                "ex_priv": "xprv3T1C3ukYQyqq9FYaHkmLGLoSdH3SGa5MYPpnvLUjrUzxRK5dMDihmtga67J2jvRMB2A1TKuhvw88hM3JzcxDKcnuTAVcjJXek44ay4o9fwjgXP1YFaT7drFy7uKmEGCR3xGZYKZ7Pzv43pENGXSiPxp",
                "pub_key": "0040e6f00e0c41d540b99f57598776a2b972bfad3b1242075f60bc9eef9406db90",
                "priv_key": "ff613f4d9aea44770a3d4368a2aa7f37ce0851ab8cd5b740f09a70c216d0e4023ea4b1d597a12ce33f7b50a82a059d15d07fa6aca9c6448aaf25d5d89d8c88f5",
                "chain_code": "cd1c51741960b27d0d33f9d78b97a6e74712d554bf39c0a498a834348f9c2188",
                "parent_fprint": "f5645b97",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6GsSmFveWuPYp5MA8vutHXKMAE7o4TFiwUqowDRuBujtd6gx5PgJaPhdfUiqpR2Xi8MNhf6xRoBAZgJnfq8Pp82n6sKjmTm3Lt3bGoPDmF9",
                "ex_priv": "xprv3TTcEc5qEsrkiTJkEYiGgjH8W8tKt1knyKTR3XnhKP7pMpA5ZpYQUNyseK7ZdZ3cszSDBwnnGZE4MNCw94xBjoFGFRqVpdpRqW6qANndf6qTy9HUn8FJeJSvZNSEpvqcXordkE1EMkD6gdyB3gP5s7x",
                "pub_key": "00b3def59036d446aa85c179c44198957fd186174bfb4dc2b3e28b7c6590d3d8a8",
                "priv_key": "a792ffd522139df70a25a418ebc2efaf9e014a942d16804118f340bb17089d0b4ff49af2c878c6b0618e3648a0cb8ff42229c6fa55879bdb2b1db283b5d444d5",
                "chain_code": "6de91475a1fe06345c10ff5db0296a658d285a9041c4b923738d27563101720b",
                "parent_fprint": "c5fd6896",
            },
        ],
    },
]

# Tests for public derivation from extended key
TEST_VECT_PUBLIC_DER_EX_KEY = {
    "ex_pub": "xpub661MyMwAqRbcFkJT4ooNX5cdbj7LrcXKzMeebV2T3RvtDMKRhYKuFbGnidP9thFCKmuTe58Pa3uTGiwqU1UedwDrEeXLpMNukEnfN9GudgR",
    "ex_priv": "xprv3QESAWYc9vDdZdB29wcbC5yGQZGVo2f6CpoqEX1jsUvMvtvdPh78PsP4QFSbxud7NHczo1pQXVLaYhUppnjdGA2b8y5iBqjDECyghRYs6TSvMtX4taZvzdChaJjNZzwFhAGL8fNGAjQt9ssFc4oiYq1",
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
class CardanoByronLegacyBip32Tests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(CardanoByronLegacyBip32.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(CardanoByronLegacyBip32, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(CardanoByronLegacyBip32, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        self._test_public_derivation_ex_key(CardanoByronLegacyBip32, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        self._test_public_derivation_pub_key(CardanoByronLegacyBip32, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(CardanoByronLegacyBip32, EllipticCurveTypes.ED25519_KHOLAW)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(CardanoByronLegacyBip32, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(CardanoByronLegacyBip32, b"\x00" * (CardanoByronLegacyMstKeyGeneratorConst.SEED_BYTE_LEN - 1))
        self._test_invalid_seed(CardanoByronLegacyBip32, b"\x00" * (CardanoByronLegacyMstKeyGeneratorConst.SEED_BYTE_LEN + 1))
