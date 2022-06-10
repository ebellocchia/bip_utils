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
from bip_utils import Bip32Ed25519Kholaw, Bip32Utils, EllipticCurveTypes
from tests.bip.bip32.test_bip32_base import Bip32BaseTestHelper

# Test vector
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFHnJTiLZTyWpM17B9Re2FwsPtDY8xguW4hC6MjhpWPhjL3fge97ogeF1gmpAAmBvQzdwTfwxN2AveXnzrpuBiZCjXDeY6pP",
            "ex_priv": "Har3K3MhV5fiuEp6ziX3dZawerevpjWQB3kpaAeTjWabW3VdNPH1BrEbyWAy4Ju288ZzuocU2tDSwFBZi2cVDtEVC83UJUyLQfkVKJBGxnZbxvHvUQos7HjeMCuuk5NpAGK9f1FV4x2MbosiCh7ccEWwoG2",
            "pub_key": "0064f0787564cb5a39a6410512f5339d152f623c623d5999af375939931c6a9955",
            "priv_key": "5c7049cb3630fb0f04b98d9e8b24a10a75e2b028d556c13877cecb6ab12e725f831a58390f707d4f623b7e2916239bfd821758e53d3e81aeac9e967714064c55",
            "chain_code": "4b11419b53d0c31c6a2048b1e92c3152f7bc1dce6469cf88787e92bc7ddd4a23",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32Utils.HardenIndex(0),
                "ex_pub": "xpub68uKwXwhWRd5ckrFNtMeT38rqqSKc9pAN6oiQJvDkiWe8wHbvMYVwYLpk3mWoD7brc5gbT5AyJCKz2rArfxZod4hZnQAAipNbkJ2oR8SNNj",
                "ex_priv": "Har3K4DbTHpBy8waMq6AvVvKphoKX4GHsqLw3TeGSFZzSnceL7xZsYH4XFqRJVHbgACSTt1xiDhT5uzKuq6DdeEHehJbG8ZALkkH15u66p5UV2SgT65EBem2WV9Rmj4CHH2tjpuqUbm4BUBAxVWpv8Zy1NZ",
                "pub_key": "00195a384025718bb6837c6956cfb4c2694e2109db70247d0e178e520a1a079492",
                "priv_key": "9cc7f5e6e1196d047ebaa17e85bf4a658395b467c4fdb4761cbcd516b72e725fd4e2ab2e4c786fdae62f0cf20ddc38ac51450ffa7c652e5e2fe1621b0b70d769",
                "chain_code": "58bf445284c6764da5fc7f97c618fda945c7eae0786c9e587705a01674ef407c",
                "parent_fprint": "89ff2e3f",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6Ao7UL2o19BhRV7fNu52aHdJsw1XzS9ZBqKnGJS6PsiUEbgCdqnxjK3jEQd7mZSBLdcRzXBLh7sw4sEjaVm5WyKqsqxBvrcveh7sgmpkKtw",
                "ex_priv": "Har3K4nD1J3YkmsFabEDv6pBw9YRJ4QSSNTDfvWNdepANXDwvdyzrPg4BEdP9GZhEpt2MUSees7Usoza1PxegaWSY9A5AyiJSYjaRP7gpNEHR2HXpsBh7kzFBFrwgybJDzCQMDqk2zcmCMwfz99EWRatpPA",
                "pub_key": "00e117108bfd8aa49c36e43229de5a34d4a3f47bdd3f6c01c797d9e8480799be32",
                "priv_key": "74fa115dddc1995e28e2e3716219fcb35dbb15886a0586d6650d14bdb92e725f4ea6c2d323978f524f0a8f52c3b5c2aa0d24a4b66f60780ea576d77c5837448e",
                "chain_code": "f1c498adec19445b947e7e48b661625fe0f9ff3bc58d544a396e2897d5035ee2",
                "parent_fprint": "8b8538fe",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32Utils.HardenIndex(2),
                "ex_pub": "xpub6CNRdGzBT7FmMzYVePz23K3QRhyBAoprLDvgV1qjFvBk2XPMypqPKycGtdLZoQinbAe4vnHYa3THsZYK5ZWjK5pyfbf77764fBhKRtUNeLM",
                "ex_priv": "Har3K5FLHudmqYrLxJJUW6HXAgbzmRQuTaXL7UPK5uyY5yHTgVXSV9EhWBXTU2rxe8aW51xbWTMjpfNYnE2t4Phrgvh8NhLccnRjaH3vbef9YiwgaxhQT36SG4hi2sLcPgeZbZvZQ2M9bSYNqtdZVhQPcNM",
                "pub_key": "004e78df853416c7f05510df794554959acbe828d0142ee4423e27c04ecb291ded",
                "priv_key": "7c3ca8b89b1ff3ad308b1d0122b322efe49e5d5565be11311920aa33bb2e725feb638bc51b3ac8c84d96a27411c5653dcb805e6fee138e81bdcdc25e2656b044",
                "chain_code": "aaa8e4bc82d306f5822ac15552f2e15a5a77c746780d638a010f3bc87de2c10b",
                "parent_fprint": "61b6cc50",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6EHrptt6h2SdFRuMbxQXUKHuZm58MUpHUWjAyq6GW48RFrvQqfrUiKgqkB49xcUVRE2d5kYkQXHCAXnmJTUnj3uGH8pmTUotAqqFRyzbvHN",
                "ex_priv": "Har3K5pSGFt5VbkpCzoqmJj7U419FpyDP2riZm5peqf8VkwPHi29jvD3DKsiPSBma2ncgh6xNjRn3Su7HBFFJyLiqte1QzLXb7DdoNfxrSWqnjZfa8x1D6XK2TEV1r7vDQPcKKdc4nXXEYfhJc2P9bECy2n",
                "pub_key": "00709e5749be8ba5aa408ce9d0d0a3418a62949f5215afb1086ceba6467d6f4f49",
                "priv_key": "5ca71d4b1c5bcb657c958d3cecb17f3e7420db0884c0008848051344c12e725f9bead4eb2cb2e9e8072544b0b5e238c6f7f65dbe1acaa902064d67543d0cb7ee",
                "chain_code": "64efcc10a67bb0a126c92d63d147f63b6881aadcb9c63bce3c20cea0b270839f",
                "parent_fprint": "671b59a6",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6G7m521kBnJYqMXHe3moZeJsv2v27yzXJcxVQHF7sdmTVS27Kahe5crNAFYKWrBzmyBQetos7NkpczVtnGM6cqSFWbBEFZmm4fYhHP7hoiH",
                "ex_priv": "Har3K6MttebnHM8BAExKttH8JkoqCQwuxFiivJ8rd7RAzgpHqQRHPseHsv6yeEaexM7LskWSa4PSNhU7D3BFZVsmv3C5A9mVi612fsnE2jojWiwfPYryp5URUrTUkH53SZFfCC8XkDppWzxUhHQj1tubciQ",
                "pub_key": "00ad6f08d27cd5cd47b964c7f06aa2430aae737de61cac4e880f6ae01298524c7e",
                "priv_key": "f4dcc232d143103716b8574c4be056be1747f2a49a0f2d477a3006a3c22e725f8c566a1c150020db1967776cd823be388a1d130474c1bd81b7cbb7ce67d16300",
                "chain_code": "8723729c056afbad73049d5fa7a71d1bf2ca1acc08ccb8bb5f2c8b1441ced67c",
                "parent_fprint": "5f84e2a5",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFkJT4ooNX5cdbj7LrcXKzMeebV2T3RvtDMKRhYKuFbGnidP9thFCKmuTe58Pa3uTGiwqU1UedwDrEeXLpMNukEnfN9GudgR",
            "ex_priv": "Har3K3MhV5fiuEp6zrPyJxoWLVRQZ5chetTUpEAse5LQz4LFtDkQCpDwGpFH6jK1yAiTZqVxhay7EKh8JNY9Dk7FBrXBkt7PV8yiVqXQqD7hWwd9iuZwVquxNyH8tryWvv5kmMHdd1LFMsqSK3KPSX5uFsq",
            "pub_key": "00b83340567ccea3de6c12c76fb2574bd68ecd8560f825632a0fb066ec149fe7e3",
            "priv_key": "141cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4052ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
            "chain_code": "78fe3dbc48c922324d02156f4d0b6508ede14c9bb62a5b542223ac8fa5745953",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub69Dx86u91nSZVTDAp7WpMLMB8oWBttyTVKdfGRvt8jVXtU4YbK8zRgJtocDYKMXzW4E9eRLNuSt4gc9wkYyq8rXRzNrhAhZQAHZg83PuBx7",
                "ex_priv": "Har3K4K8LPyT5mifnxNoEtHgR3J2c64hGrHSWZbk57Jo3YmCxKKosGEtk8DtmwHfbaRwpxqSpRcV4aM8SfC4Nrcw2Vqqf4aK3G25Atf71jx1XeKj9fqp59ss5GYPq5SF6BN6h8rVashn4Rc5aTx1YnxhTsF",
                "pub_key": "006aea7287bda004e2888b63184cc38c55c570fcc8bd1743f00cd01bf3f1d4dd9b",
                "priv_key": "cc3012426d1d637e33a16e1b08ca1cbca47c613999b993e6e23b14fb21ab4052d34494810de703778c504b7f3b3d317958e05778ab05f1c9a25e47e6da9cfc64",
                "chain_code": "05b1d2f9a26711a0f40cdd3abc551c9d53d1db13803a1dfb95898863ec17b51f",
                "parent_fprint": "b5aed0a4",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32Utils.HardenIndex(2147483647),
                "ex_pub": "xpub6Ax5xZRw79cyFMS9XBRk6Cg7pt9d3rJPREBiQa2PDFrffYeVGwHqVCnd8VkkGGcR3ZcfzgaP4Q7TjJyv68htTNm7XTag2AsDcBJ2sdqRnHa",
                "ex_priv": "Har3K4psd5A13asHmKcUa7zNvtBvSUiRiPw613Ga2ZWsmzD5sGPz8uHpHrFxWkZLCJ7wkon1zN3Tf4dwtEN8qqzhqhhePiBQYohWXii1GQuPEhMk31qrJpgzKWTsMrkGBCdtfYyFdRrTcUaX1NENUfkdeZ5",
                "pub_key": "00417a71d304969be0030ff9d1a731473d8c2a14c5f6269a320951a8b2972d8540",
                "priv_key": "84f2f4173db62056d1c0fcb2bd46b3431544d7d706f595533a1312cf26ab40523ed6aad9488eb7e4ee87037b924696ccd99009c9f4ff2422d85fb5c05209d36e",
                "chain_code": "4d8d635c289c1229709d2dfb0f7c9f569a3bfe165ea6b12071725557e390c75b",
                "parent_fprint": "a092110c",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6DT99VfDBLzfNiSCksHDJo1H6veswCWdg2mSKZarxASR6ULwW7Dt5uDDCSxwvpaHZPW9mLMxHd1u6x1cxXY9qY2wpf9LdP98FjV7TC22d7M",
                "ex_priv": "Har3K5ZxrwFbUxywVCLKMadQdUTd5H5Quda7Uid8zJw5XhSZbyeU4KMPoa3K38YNgtWKgDsid4dJi445qsoJE2dYmEy2qj63MkBiPcAWincKY2UDWvSBnLEGPBqVt6QtCZmQLxGCAAmTQWt33a7qJC56PFs",
                "pub_key": "00e263a547775377a3059e5ee40676d4e4d1ce6c6a3476cc3091767f7c94831c44",
                "priv_key": "3485924081da165551469dc73ede13b172f6d4d01bba2fd24b37f51628ab4052631becf699f95b762b3013c7c5e92e317389404d33944fe6678ef48ade55c754",
                "chain_code": "485eb29eb5bf09ebd09aff81af953fde4865e7b9ea749e0fe8f9f3570ec6c650",
                "parent_fprint": "f4d3c377",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32Utils.HardenIndex(2147483646),
                "ex_pub": "xpub6EoBfvcVq2Q66k2vSkQ5jKKTSP5cQGqMjc8gGsY46EiRrSqB82pKwG4ZkeH7bhC7rbQTiddjGY7ae5W1SVTUgCD64gnwVWEap3mpcjtKKUX",
                "ex_priv": "Har3K5y9X96VJFWQp62bcvuRAqUKkWJq2VijveAu99ey2hVyEeHWjzKaChPupog3ASTL5HUvtn9hb4MueUVtzPwZx6uyiSqiShW17cQ34tfp3UaFrS56Fu7zBXmZQnqPDNYkJJZWpwDdVPKtLJ8JyQhqr6S",
                "pub_key": "00619dc7e52d1d9ca196329705daee63823c5d67f4ec4928138625af509c78dbe0",
                "priv_key": "bc23389c030a2a76168d857eeacaed801f2b44c5a1f3564d74ff3bef2bab40524019acddd31156d0353ac24176bf0dd804a0b629897de99a5d2a23ed0409eee3",
                "chain_code": "1efdb9ea55a9c7da9cda043dd49428ed36554bd4dc4811bfe10f737e482ca0a4",
                "parent_fprint": "abe50074",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6GZAxW3rmuxvuJrRUH67Hu5jZxQqX9HureChk6XvFaEJ2XLSfEAFJMFmHycCgtFCjuKQLUmtVRQFDWwQc3aeJckzFY8CTZ49nUK4DQcwhER",
                "ex_priv": "Har3K6VSj9Bvc8GEu1wjYfGUCPEhhzGA9oyaEQS9Rz3N7RNTAWM8EefT6SXxdcxxpz7gTW3ynoKxQSBHvzWMd15k12ViLSiN73DyVznVddraYZpJ2k48UJhsBc2J5TEPbPaoaRVL54c2a3DUzH6C5x6K582",
                "pub_key": "00267280fc10f45992e2ae9ecefbb188f0ceccc92d4e24abf07b7b7120c93b7e5f",
                "priv_key": "e4b4bb5ebdcfddfe2bdbf2ef4583cc90bc163c13f48028781c29b2f42fab4052f4f37acb7b269b9d4ab76e9ce1295bfd806a29fa558eee2a0af061f62e99f407",
                "chain_code": "c217317478708de9c95d4f5ed3a4cb847e9e30ea986e892f2f718f08e523f468",
                "parent_fprint": "9b20bcb7",
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
            "ex_pub": "xpub69Dx86u91nSZVTDAp7WpMLMB8oWBttyTVKdfGRvt8jVXtU4YbK8zRgJtocDYKMXzW4E9eRLNuSt4gc9wkYyq8rXRzNrhAhZQAHZg83PuBx7",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6Ax5xZReRpZ2xtZYpPZeWbUnPCSJP2DjLMWUd9n9NY3hk88Azqthum2SgpZqd5keKXnBPnArNH5nVrWfHtRMg1CiFLw3zsn8joiuGQ2KUb3",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32Utils.HardenIndex(0),
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
            "index": Bip32Utils.HardenIndex(0),
        },
    ],
}

# Tests for invalid extended key
TEST_VECT_EX_KEY_ERR = [
    # Private keys with invalid lengths (generated on purpose to have a correct checksum)
    "DeaWiRvhTUWHmRFa63ZawWQy57DX4NvP62TfD46boXurKLAgyUEp5Xz59LLRSa4sse2nscJCmFC4DvmScVSuJSxfQAzFhxDc4RV85PtjgAwLMX",
    "5FQFKc7mTW13jdERCczZfzcHum9pTkjqVdP6HZCVtfC2YAjAT8RnDG6Lmo583qUQx2toUpuxyEJFVgAp725tEfbUJqXEA1WCgm8Qm4BPft8otyZpr",
    # Private key with invalid net version
    "yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E",
    # Private key with invalid secret byte (0x01 instead of 0x00, generated on purpose)
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnListey6gETHL1FYgFnbGTHGh6bsXjp3w31igA2CuxhgLyGu6pvL45",
    # Invalid master key (fingerprint is not valid)
    "xprv9s21ZrQZgP7FPptNcV6ZuWeytnfAsNFoPXFUTMDdUQpc44ZhfkDAnctGeUuywWTKXEFwLFGRPGd9WcjbTDdjKU25eRw5REDTVxfiAxZFhrV",
    # Invalid master key (index is not zero)
    "xprv9s21ZrQH143K5p8oLYasVfWDcfK9E5HPajvc6vEmTG592KSs8jk4fb3vA6ZoueJM4oi7xTrbbfU5MyTPRLFPbXLr3TZjQw4rXFQ7v1sk7C4",
]


#
# Tests
#
class Bip32Ed25519KholawTests(unittest.TestCase):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(Bip32Ed25519Kholaw.IsPrivateUnhardenedDerivationSupported())
        self.assertTrue(Bip32Ed25519Kholaw.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        Bip32BaseTestHelper.test_from_seed_with_child_key(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        Bip32BaseTestHelper.test_from_seed_with_derive_path(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        Bip32BaseTestHelper.test_from_seed_and_path(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        Bip32BaseTestHelper.test_from_ex_key(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        Bip32BaseTestHelper.test_from_priv_key(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        Bip32BaseTestHelper.test_from_pub_key(self, Bip32Ed25519Kholaw, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        Bip32BaseTestHelper.test_public_derivation_ex_key(self, Bip32Ed25519Kholaw, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        Bip32BaseTestHelper.test_public_derivation_pub_key(self, Bip32Ed25519Kholaw, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        Bip32BaseTestHelper.test_invalid_ex_key(self, Bip32Ed25519Kholaw, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        Bip32BaseTestHelper.test_invalid_seed(self, Bip32Ed25519Kholaw)
