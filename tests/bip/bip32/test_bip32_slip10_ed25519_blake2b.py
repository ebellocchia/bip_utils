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
from bip_utils import (
    Bip32Ed25519Blake2bSlip, Bip32KeyError, Bip32KeyIndex, Bip32Slip10Ed25519Blake2b, EllipticCurveTypes
)
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import TEST_SEED, Bip32BaseTests
from tests.bip.bip32.test_bip32_slip10_ed25519 import TEST_VECT_EX_KEY_ERR


# Tests
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_BLAKE2B,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFybaNRzmKwjLEeQdU4ciWTZ1zPxvvN683xNT57Gr2k7YbdqBz5N5NdqeCEhiZLvSmZE721EUipgYL2v1QEGunyEs8JviJ6x",
            "ex_priv": "xprv9s21ZrQH143K3VX7GQTkxonbgca94bts9EdRC1ZKN2Z9BA3JXZxbUwo4kS28ECmXhK1NicjQ7yBwWbZXgjRVktP6Tzi4YqetK5ueSA2CaXP",
            "pub_key": "00835e3307bf32df124bc0bd3e3d5eb4a751ceeebe06b69fbce54fef97bc37c062",
            "priv_key": "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            "chain_code": "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub69F72R5LsVNeZxu7hYqxueqXRsieg29CFBMAd5rr1YuAK4CCuG3wc7dT2pucqZppRkHRDGoRyvQNHLnSVPYQ8Eph974t7ok1k17Q56yv79x",
                "ex_priv": "xprv9vFkcuYT37pMMUpebXJxYWtnsqtAGZRLsxRZphTETDNBSFs4Mijh4KJyBcsGNuNDY4SsYz8pwQ4L9ob2Qw2gviLdtQPAwG3t4Wf8Lb4rrXX",
                "pub_key": "00df1f51aae49a3c17d07f603ded31c409e4c81fa8b32425a7e0de4143d3cfbeac",
                "priv_key": "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "chain_code": "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                "parent_fprint": "b8637b7e",
            },
            # m/0'/1'
            {
                "path": "m/0'/1'",
                "index": Bip32KeyIndex.HardenIndex(1),
                "ex_pub": "xpub6AkbKPpK7LJz2za2212Vd7UizLi8xUjrJ7F8WKdeLELn4w9kXcAqvNG2T8QD7Zn1ovwkakHq6XcRtiQqij88neLYeXj3Qf9pWVW6Dumei8D",
                "ex_priv": "xprv9wmEutHRGxkgpWVYuyVVFyXzSJseZ21zvtKXhwE2mtooC8pbz4rbNZwYbwAmqv27khr8i1EbNcnpzi6sDFK6SZw4BuuY8FNBtdbzzjBco1D",
                "pub_key": "00bd8722955d817dbae068d4242cf318df57f7367fc00b630cccbeab541461db63",
                "priv_key": "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "chain_code": "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                "parent_fprint": "859c0563",
            },
            # m/0'/1'/2'
            {
                "path": "m/0'/1'/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6D5HzMKzmXodQ9d8junuPDHxK9JDoCuZkgcCrzghG9Ar3YpwkhJ6PmDXJjpNcgZGVWiv723zTr1JBgEnV1DL2sNRKwLyLwriVEU44BttPAZ",
                "ex_priv": "xprv9z5waqo6wAFLBfYfdtFu25MDm7TjPkBiPTgc4cH5hodsAkVoD9yqqxu3TZUjE69TJnsSaYVXKCJ1CTBEq5ZdQs45Mez2A7LkbzC185tTSJb",
                "pub_key": "0028c30a92b3979b69e2ec354e2ef1cfca24196ee150a06e526b56a1105cab1d28",
                "priv_key": "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "chain_code": "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                "parent_fprint": "c19448d8",
            },
            # m/0'/1'/2'/2'
            {
                "path": "m/0'/1'/2'/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6FEZZoEe7QivJ6GY9iNkNdVDXQA888BqBnYUEL28H9rLeNFnz48WBmhneExh5yDYt3aH8jGM3Q1aGVHtm7rQffeH8BEcdmXgZSNzUyunfwn",
                "ex_priv": "xprvA2FDAHhkH3Ad5cC53gqk1VYUyNKdifTypZcsRwcWipKMmZveSWpFdyPJo2jqxi9TDiYKJMqDPXy9wjWdV5cYQFZpTyvffhrC9j9ZB9JVncd",
                "pub_key": "00bee444619590fded09ad8feba858e2f3d8e70558334e485823190ebcbe33a49f",
                "priv_key": "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "chain_code": "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                "parent_fprint": "e76c3758",
            },
            # m/0'/1'/2'/2'/1000000000'
            {
                "path": "m/0'/1'/2'/2'/1000000000'",
                "index": Bip32KeyIndex.HardenIndex(1000000000),
                "ex_pub": "xpub6FuK8FGuw6rKCQYKFSxCG52DpDTqkwP9R8Xc1iroT47uRMRif4rRKEr2jkWqPHdpoc91j6gTdWohWUnhSXFdv1D2g3rd4cihkg1XjmqLr4P",
                "ex_priv": "xprvA2uxijk26jJ1yvTr9RRBtw5VGBdMMUfJ3uc1DLTBtiavYZ6a7XYAmSXYtZVzLUrWX87zGgzmcvb2XQpjyceqC7bCVsuraMhbPr7KHxFqqTt",
                "pub_key": "007eb4e91c8dbb1889c95702161226261dcb188e7bff56f346523a558bba95869e",
                "priv_key": "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "chain_code": "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                "parent_fprint": "42524194",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.ED25519_BLAKE2B,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcGvhV67CLpH9pkuL15VmcXENpThobsvTXHrSRZ9cq4oRJS3H86voPmhYqF5fzJTjiHzzofWTNsaoFRwkghnBetQnGtCadpHR",
            "ex_priv": "xprv9s21ZrQH143K4Sd1z5fLT9D6CsVWg33mA1TDfKPzKavYR47H1cJaX16paqoyUuw3g1Zm6GHruGNpXqdVk8BVoZ8bLE3DYQpudN4C9H391kJ",
            "pub_key": "0041f62e2f807827cc0cdedb67fdf3613c225750a45fbdab74d34260b120919d64",
            "priv_key": "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            "chain_code": "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub69WoudRbvLBUyYd3cAcKaTH5gi5iN7xzmnm6hBe8bDUyTkSgaXeVVp5qSyyn97kRNiAoMBuYZz2nmFJZToPtgowNA1bXPw7HPwUHsSaNcL9",
                "ex_priv": "xprv9vXTW7ti5xdBm4YaW95KDKLM8gFDxfF9QZqVtoEX2swzax7Y2zLEx1mMbnc2ctztRd2quCcUEikzUHsDM17BhbdnDCJbHmyRNTzC5X1NtjR",
                "pub_key": "0033f17910a526b0f0d39342d35f7780e144fcedfb7cfc2aa3bdaeb48d39b7d9b5",
                "priv_key": "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                "chain_code": "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                "parent_fprint": "dd3a483f",
            },
            # m/0'/2147483647'
            {
                "path": "m/0'/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6BZ1d6maAzztpLZjM5hZKiTBnH6LRLqjZ2FNFkG5DxC1VxZSrc9XvfTQsbLvtWcqkicJUN9AxmEdnd3nDBFcrYMzJWWYnagK71GF1qz2DAv",
                "ex_priv": "xprv9xZfDbEgLdSbbrVGF4AYxaWTEFFr1t7tBoKmTMrTfcf2dAEJK4qHNs8w2QSVQXoxcsr5fPuJVNHdrtH5HRFoRZwGWYgNS48AvahYin4eFdQ",
                "pub_key": "00cae39681005a9a9872201ce75cd8aca355018d42673c102eea2e07c90061ba79",
                "priv_key": "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "chain_code": "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                "parent_fprint": "f27eb93a",
            },
            # m/0'/2147483647'/1'
            {
                "path": "m/0'/2147483647'/1'",
                "index": Bip32KeyIndex.HardenIndex(1),
                "ex_pub": "xpub6DCPyKD8dN33VVgavTgar2nyxvJL8oUufEkMHdm6Hq5i2qMeEHAcUwmfiKUpWQMBuxDk9fNYfrLP1h8eYGj5d2PEpYpr9rLJKZ2qQDbiguB",
                "ex_priv": "xprv9zD3ZogEnzUkH1c7pS9aUtrFQtTqjLm4J1pkVFMUjVYjA32VgjrMw9TBs73StshNQVh3qLrQRFoAToNnrWufMfne1Nyooobk9dGG2Fn4otw",
                "pub_key": "00e1db1529a0369d19c385973685d7b6f85c700726caa437ca2058c94e083e5202",
                "priv_key": "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                "chain_code": "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                "parent_fprint": "d23dbab0",
            },
            # m/0'/2147483647'/1'/2147483646'
            {
                "path": "m/0'/2147483647'/1'/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6F2wNucu1acFAkVknVaPiCLfPHCCivfsMUGkKJZcu6NRA8BfsSZ1rBzN6m9vH42t63igBiBz1v3yRd75sr4T2gXWEV272aoMFwbdhMWR6Mt",
                "ex_priv": "xprvA23ayQ61BD3wxGRHgU3PM4PvqFMiKTx1zFM9WvA1LkqSHKrXKuEmJPftFaa3ZcNASRcWpbQhHsPVo3w9KW5zcpfxuFdoEA2DKKhx9bZeP7J",
                "pub_key": "000ea4400b51726bac926e67a6c5693fd4ae57b20b94bdfd07345808936980d16c",
                "priv_key": "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                "chain_code": "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                "parent_fprint": "cc280887",
            },
            # m/0'/2147483647'/1'/2147483646'/2'
            {
                "path": "m/0'/2147483647'/1'/2147483646'/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6Go72bd6UdaYCGMHFS5SYioB7VUfx1jV2RFUTehCi7tydUxVXLuwpEWXrb9DfkGJjired98btGZoGFUL13QQEdoqhEBLdpYWPsDmzzQdM91",
                "ex_priv": "xprvA3okd66CeG2EynGp9QYSBarSZTeBYZ1dfCKsfGHb9nMzkgdLyobhGSC41NmrX6u3qHvrjYWg3VGDrkZQLmHpoTiKMksBBMfibvmqkj666Qq",
                "pub_key": "00f686bdc2f81a7e91d39d34a18b8e799c63c85a9ff96ca140953682b83c3c9d24",
                "priv_key": "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                "chain_code": "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                "parent_fprint": "bbcf1281",
            },
        ],
    },
]


#
# Tests
#
class Bip32Slip10Ed25519Blake2bTests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertFalse(Bip32Slip10Ed25519Blake2b.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(Bip32Slip10Ed25519Blake2b, TEST_VECT)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(Bip32Slip10Ed25519Blake2b, EllipticCurveTypes.ED25519_BLAKE2B)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(Bip32Slip10Ed25519Blake2b, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(Bip32Slip10Ed25519Blake2b, b"\x00" * (Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN - 2))

    # Test invalid derivation
    def test_invalid_derivation(self):
        bip32_ctx = Bip32Slip10Ed25519Blake2b.FromSeed(TEST_SEED)

        # Not-hardened private derivation
        self.assertRaises(Bip32KeyError, Bip32Slip10Ed25519Blake2b.FromSeedAndPath, TEST_SEED, "m/0'/1")
        self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, 0)
        self.assertRaises(Bip32KeyError, bip32_ctx.DerivePath, "0'/1")

        # Public derivation
        bip32_ctx.ConvertToPublic()
        self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, 0)

    # Test old class
    def test_old_cls(self):
        self.assertTrue(Bip32Ed25519Blake2bSlip is Bip32Slip10Ed25519Blake2b)
