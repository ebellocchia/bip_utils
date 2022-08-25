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
from bip_utils import Bip32KeyIndex, CardanoIcarusBip32, EllipticCurveTypes
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import Bip32BaseTests
from tests.bip.bip32.test_bip32_ed25519_kholaw import TEST_VECT_EX_KEY_ERR


# Test vector
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFEeRDFZks4ibU5Az847R6TiMuBvVPce7zTSAaq4bqEibpgRpSxYy3y1Q5CuNLsbAFqNW66wCVpkXG3LLEMb38HgvENa6MqT",
            "ex_priv": "xprv3QESAWYc9vDdZUN4hCza3hy8hfCj3wKi8ACfwm2U8JUSektXJGveqrZUBdnAWBmKEt5HEayb69XVkW9QV5CusSwbr1sPZrxMVBd5A2wkHkp4846boij9qKwdQTRMdkVV8WyDxuKwoJVSoCANB66B8iK",
            "pub_key": "0026a0a7144417696537eafe6e942715a6a06e4257531023dba17b33f5a283f5cd",
            "priv_key": "c06a3f6b48d90f0517dbf244da40cc25feaebc91bee5b92e2d9301db51520f45b3469692e2bc05cf27f7e4b749581b3719a37dc3045d69da8c0d826c88b80f57",
            "chain_code": "45a302ecb459a48b23bdf5ca1f7c5ff6a46c4fe17c30751fa49f08f4fd564a7a",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub69Z4dQxSvdWH2ysfNjdyUdXgCRbWxjUC4gMfsEJbR44wUYMUdwoDBkXMokkWwPtMoDG87HhKNvH6B7Z1fszrjRDhy4ogMsWTSqdx8hJQCPy",
                "ex_priv": "xprv3RHYJvpHm5rVaD5gDZavWKT9qigEWVhasonX4cMQmRAR5Vpy4DDWenpxfDkK5aQbEcZC8qyJSjLB4wmfRigHftDwWaUGxvS1Jn1DU8FhmGXvszAgAkwcQ4QXebyh54kxRx2wKwxF4EQQnTg6usd351R",
                "pub_key": "002bfbab7b4f35d96e8bab92933604705661bb3241df7a48a3b5df8c7495e75488",
                "priv_key": "c09061c89691063c94ec4f4533278e4cd24dc74b439ecbcdb1f6583053520f4524d6690f98a0c6c41c20d4b9504275d4a8141913cf9ec176423b4f63afdccaa8",
                "chain_code": "66c98284a8ccbdc2209746644ddf1fdf469127e2147b8c573c0d5837b3a2bc26",
                "parent_fprint": "e283b13b",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6B8RZjPYsAYVH9bokaERjvGeUQeGxMJGH8ga42c7XwZUbHHDekeHd47QymDh5J4KLZowRTKDdJC297ZrvstmnJTR4PfKPVWaRh97SytoFM8",
                "ex_priv": "xprv3RkgRUkZh1UfoYyyT88ERK5eV4bovAUT5p4pgSVbpgS6ZrvGr8yLGbvcSDjggj48R9LDs8W456nKJGJkn6ih5fekbEFhuCiFvCJQY189o7oMfFWXMsvPSpG5dLkEmbAdXW1b5RHy4htLpj9kjbBujp5",
                "pub_key": "00313342ad062c82c6aa8e4b5a7b7d1dcbe9fc2bc5965c27a34a0f66b71e4d41c5",
                "priv_key": "28bc18db5c45587f7124863256014651f51d3146552640c647dad4275a520f457a83dc9302f12aa82fab95e25fe162e967a987c277063f3c6b5c890455a8b1f6",
                "chain_code": "6a31dcd5f180f4677fa33086fe71899ba061d0a26b7d34ec3b49e1b1d244adc5",
                "parent_fprint": "b8d212de",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6DLLqy8mRAUa67cNEmc7kMhDRf1u33jhquMVWXWTdJ9ysagvrLjjmhFWuc8DeJVhyufsZVJBjJbz455QmJffanPiBtdPXmMg1FeTfEHPHAD",
                "ex_priv": "xprv3SQgQhN8pveLVUn34CSqig1TAMjppXEVTt2fZMXZakWM9aDcQsqFjxEBmJbjGtPJ6nHAdkaBniVEmMGBe9uoJ7WUJAKeUykfnZb25ybsoD2ddGubEWWuuyxuZNABvBTVzeDhPUeoNePDnLS2to5jGTk",
                "pub_key": "008c5b24288602cebcac92391d1a71c08ebaa68bb5f92be4b46c5cfbcbf2524d5e",
                "priv_key": "e0e9740089a9b58b715936bf1c35f54307317a4d9ce74c501f7573715b520f45b2f70a3d1647a08c5b0488761b95a4c0d505e9dfbdf2a0c407669c300b032148",
                "chain_code": "c513e21bfc7d0de3cf019eea541337dfa87fb4333d4f0a97b54c1c96c0fdc4b3",
                "parent_fprint": "e4e15e20",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6DYxdnJXzRJkCcXxj8eKnFaK9NxgBarGKBw2tGkreGRAosjpf8deE1E7KoXLeUwzVNCA482buCaRadGLhCegtvQzYxhsY6Ep5LwK7V6jNDL",
                "ex_priv": "xprv3SURo9F1Y9EWoNdMFvTCVn6M3wNLajN34gRvHWucvz8yv7t1tkDUzYX7i5NffCAcpbsBhHYuTdYUMwvSHLGHWBVJdbfcqSTtHJvPgwJNjpyefhKsRQQSRALd4xR3jE2pT8QeXLQ8DfthzKvdeLbRdHJ",
                "pub_key": "0001977bd34879d0b0482a0a45a437d1e2dc7ba01b2ae90d2c1304c2e2bec23913",
                "priv_key": "d85fd7d96f2d63e0afa3b2f708163b1b43e00424c0ee607e745e7b0e5e520f45934e905b1962d3a73f96aa89bad742c921778e7abc567e3f9ed497b760ab5d87",
                "chain_code": "3592e433c9abaae33aa32741413809428a9187c1bbd03e7644d4bfe81ef9bef0",
                "parent_fprint": "0279eeb5",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6G16A3rP6ix3ryqW7UG54tAhyXrNVTGMss66PFLuUbA6tbGRspNXijSM3FApD7qrBSyWX4ZNyNKq3WaofHJDB4HKyTR5U16rfRYcKEDFHCQ",
                "ex_priv": "xprv3TCedibVboRGTUzDQUPFd3U7ttLV8E29ZM6N4US5GBHr7RAG31yLxXvjbyYyAPYnkNzmQC66uid4TTVF46qiT3tTUWdyxum8QVQ32ZbGWD58hvoZVauRZq54LVJ8RmsvVwMZk7PNo5Rb3AfZHjxYQeN",
                "pub_key": "006870b306027ff51db0eac318455c032c57a97ff0fe5edcd124b88c006e6c8664",
                "priv_key": "d8e0ff93ab4a1d749049bf5494d7974cddad07732fd343ffff46b4895f520f45996bae08ad8af4f925950f3e5189dbbcac02af46cdcd8daf0d537a051177a62e",
                "chain_code": "02d93b552bbd1201ece9d2fafda74a1b66f0ac6cdec8680a3d4726f232e0584e",
                "parent_fprint": "4fdefd95",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcG5KVPEA8nKpdZ2AbneX8dBwy6u5wyAHNAmAe2q6otDso78LZvcMVxjBDLVBFBo5NAVtSz9mwWALtm3wCMsAc8TRAmsVfzxL",
            "ex_priv": "xprv3QESAWYc9vDdZiph6ERCGcHPF3w3goaNFQ5YmwHv5tDxccjpWR5XhofhDMkEidYzG2Qu11WYJgkaVep8oK6sXpb7YxAJ95RtYSoRLjH9Vc8mcapsKHs1wviKcmZTsQrTsauRU5HftygHMKkxFVdG6Vd",
            "pub_key": "00ed87b6b2058eeeb2d9c32936e8f7e8b856870e7eece1ef2436df1e33b60861b6",
            "priv_key": "c8d7d2d7e743614526ba29eac5079d56acf20b9e8a43e69142083635c6db2c522e69de756e9b53b475b70ed4802a9f73b82725da60385c9f3187c82568ed49ba",
            "chain_code": "99ed6ee06a511a639ef62b470f123a442fe219379ea312e8e78937ed74e7e749",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub69aKPpga7aZRx5SGdTbarD5Cq7kcgKynkXuP1pvznsc1TFQLnqMo7QroJubxC6USae4B7bpkNbwgHQapNpL55VAzTVTJLBQt2BjGKPUmjzF",
                "ex_priv": "xprv3RHuvemhsQY5VLd4Kn1qvLEV48KQ9iBk7LwQJbLZ8Kj8ZihKyvSTd24tvJqG3G2jQuxY8RFqcP256qNpHpzu339KdFQueLZRDKwXtb6A1dvxZJ9VRZbFjNUHJGXwnKVSiV5xmW7vGQnqMLhHF6QDcqT",
                "pub_key": "00fa0a707eb43b245522a19674ba2b8735600f3aa4beb884e9936c2f788cac16e7",
                "priv_key": "b8da9f980f797d2f4731de4f020141bd0d4b359cd0c51bb5852d339ecbdb2c52341f87ad34119038cab17ef83d694175404305f1b09dc5e22d5e26c64e514d54",
                "chain_code": "4195ce929e96f610fdf5ee5017f093ef832acaeab7d187a30b1eca5bef44b284",
                "parent_fprint": "e57511ce",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6BHEib7hMS2igXMbmrM6heY1BBSLvdPcWXnZQ2XKehKqzt9Phzvoh9SuFipem7LS4GkLBRDbdL3DXxDM2Pd4un2PbvipXa2T5RVTuX6rvdL",
                "ex_priv": "xprv3RoJGSDFymNPmZ3is7whBeQtyk9uRF9JFqMNb4MdfEkXeXb1fANhbrBk4yscyB6mz9QY7eTGCswdoYNZhugPGkfZFxzoTHTj2nENztNGJY2md36zcKSqejecfaGX4oGdQmH2R2AVaKRiSbZ34inJqwV",
                "pub_key": "0083c0d4a91cdf5981df0055f8e7ef5892dc4b979d962b64ed944a197145b722f2",
                "priv_key": "78d9fec55d77e85a6e02d33b5f95d4cadac421596a358f4df9daa6d1ccdb2c52f63733ee12a3390c761da8c70691cb1376f8fce9155eb4184db7fd684200f66a",
                "chain_code": "f5fda85dd882c70dbd982fdfa77009f43124a82e8a956feae4a3199059b09a76",
                "parent_fprint": "cd7e4730",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6BoqrLwxviYqtQmGEzyRwHEABXhUKEHY5d6M7r1ys52TJMyM6accXGFrdbtyLqsH9VV1yddv2hYDysin1yLFhrt5jyUoqYgFVWUn9ZYzyU6",
                "ex_priv": "xprv3RxPbH3YssZr8YZATwmM6qG68B5kV1ZnmYPmDdonHyGGfqZz4AegybNra6vEHCzn8XHej5siwP4jFEN65FVh4LXS9dmrrjx3hWpsQn54qfWDJQfqV1LtaKLfe6cHGC9bb91br8sBBKAZ6HD1MFtYKrk",
                "pub_key": "00416d7bce0c3c03e287c7e6b3dfad5a6dd69c8c4ceb02aa8f7e0a3473f088fb57",
                "priv_key": "f8d13fef1199d1e111118824533776113bcfc641ecb38c8aa039afcbcfdb2c529700010ddb6605b68b9d4608ef2bcfb79de26f3e2048da9e770442148b9d0be4",
                "chain_code": "fdd0f58c575662110bc6867de2aa31f70c5f0cd7264e35abb917a3327ee51436",
                "parent_fprint": "1549127b",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6EyHnQMWz4BNRTYLUza23S28MxvaxUv2pYojqbQYNjuT6VUTYPETFVEWKARLVivRdgLbmLMzrgue8dyuwBYTyTv9N4bVs8xsGZLzDkx7Gcc",
                "ex_priv": "xprv3SttK3CSQhQXkuz56r5UAvbo8RuZxFQHT4sLdtScbpkiSYsvJFBupLMbFQEb9hLdmyvwo4KuBCe3FPsBEvaGbSkvKDpjTLMU2qbcn4YNdSPLgXJszfcXPUesYoaLRLcGJrk6QwSH8w3M8Zhf5vM16SZ",
                "pub_key": "003b8e51e417238387cab33c2ccb2f2603fd142e0f594d885ef809a890d9c56675",
                "priv_key": "709578f125d293577d6dd01c15c09bf0ee6acfe35338c2cf923e98f5d6db2c528865b7c13818b656e5009bff24775ca145aa291a841019e210fa9a8affc8002d",
                "chain_code": "62ac61184a4e79c56f2a04a35895bc0889df29098a52774621471615fc0ed7db",
                "parent_fprint": "c3994ab0",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6H9XDgii3oxDrAebqtXUoxRCYTFdA8dSaGjZQss3aytK3Li9tzbFPQZQrgKjuTSsN2vg55Ceus1X1e5K1NjS3ZP2J4qJ13NLZbcpMDQYAAo",
                "ex_priv": "xprv3TYPEScghJPRbJQSci7rkEnZDfziVuB96a5jSfefjJYVCQbZytSVv4dU2S5gWBFhqigZRmbz5yWTCdwfu4PGJyYFoJkSDpGAv88i5PzyUThpnWFgEqkBAoZ9w5ZWBwh16M4CKqwv6SZMGC8dWZPCthu",
                "pub_key": "00564588eddac7bcd4cbcb8c19bb4514cebaca665c376d3a28e51ae5c1a2d8cf7f",
                "priv_key": "e88b86f4eeac93d727b7ef348d937cb5559ad8abfbf866ed2c52cb82dbdb2c52f40ac08fc444747ba30aa65e9f3f079e6091e4bf09ca6e745bd94db07d9d1790",
                "chain_code": "956e5393f2ee98c2a7c8058e9b2956202d03bb04ebc5d8a8e7336ee5c0e0a569",
                "parent_fprint": "ebb38f70",
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
            "ex_pub": "xpub69Dx86u91nSZVTDAp7WpMLMB8oWBttyTVKdfGRvt8jVXtU4YbK8zRgJtocDYKMXzW4E9eRLNuSt4gc9wkYyq8rXRzNrhAhZQAHZg83PuBx7",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6Ax5xZReRpZ2xtZYpPZeWbUnPCSJP2DjLMWUd9n9NY3hk88Azqthum2SgpZqd5keKXnBPnArNH5nVrWfHtRMg1CiFLw3zsn8joiuGQ2KUb3",
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
            "pub_key": "008af88531ce3daaad84ed0b776c2b17c43a77561caa5d187f669531dc4c5bbadc",
        },
        # m/0/0
        {
            "index": 0,
            "pub_key": "00483c4c636ac73f9b743e502605960f4c6302c629610530b682cf4ae0a73e20d2",
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
class CardanoIcarusBip32Tests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(CardanoIcarusBip32.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(CardanoIcarusBip32, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(CardanoIcarusBip32, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(CardanoIcarusBip32, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(CardanoIcarusBip32, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(CardanoIcarusBip32, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(CardanoIcarusBip32, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        self._test_public_derivation_ex_key(CardanoIcarusBip32, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        self._test_public_derivation_pub_key(CardanoIcarusBip32, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(CardanoIcarusBip32, EllipticCurveTypes.ED25519_KHOLAW)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(CardanoIcarusBip32, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(CardanoIcarusBip32, b"\x00" * (Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN - 1))
