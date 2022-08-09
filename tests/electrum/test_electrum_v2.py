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

from bip_utils import (
    Bip32PrivateKey, Bip32PublicKey, Bip32Slip10Ed25519, Bip32Slip10Secp256k1, CoinsConf, ElectrumV2Segwit,
    ElectrumV2Standard, WifEncoder
)
from tests.bip.bip32.test_bip32_base import TEST_SEED


# Test vector (verified with Electrum wallet)
TEST_VECT = [
    {
        "class": ElectrumV2Standard,
        "seed": b"a1fafb7236d235a63c3f74b454c5a62f37a1c1d66d72aabe32821c2166f9d20102998d23a5bd3cacf026ad0223594919976cdf81ec4e232433ba041c9aa94a42",
        "master_pub_key": "8a6ff81584addd88793c78e21e5e1ba368abaa7d156947d97b89c2faea6ca0b94fbfa9595b42d0882df1799786bbf89aa75c134c9e997207a03e48078f8f5049",
        "master_priv_key": "L444hxha5z7pozCRoLQfR19Gfo6osvVEVSjDiYzWJY32SU6uCyU8",
        "addresses": [
            {
                "address": "17kW2sN8CNukRghwgtvadWHULHVtb5JQgq",
                "priv_key": "KwSLpK5wyGCGfipttdWEUwnLZawuLNDNshG7dv9mxMk7TU9uBrXp",
            },
            {
                "address": "19Dnzmvoumz1qBBu3EJg2Err8J29UDRRZ6",
                "priv_key": "L1uvCYc8GiaTnfD9sSCLCRoLZ5g496xfBhj2FfGxvthyG3bv74SQ",
            },
            {
                "address": "1Bu88JzHbfadMedfjzdruuvh91CCdh8LY5",
                "priv_key": "KyQTgivefDMRGahWFQhtjWT7Xwe6kN9nmGXgNi5cZWKohZPGnhxF",
            },
            {
                "address": "1HW3fCBBCEx4D7a5cSjrUNdZiVoSdLWWW2",
                "priv_key": "KynQCktf6wtKBtMbe2BDxbGEsQPE3n2k9gTY2NVsMbH7W1WDCyRL",
            },
            {
                "address": "19VUJfVSsBte3R9p6EqrsWZBHmJqoSCZu6",
                "priv_key": "L3pqNyvwBHR5UUQszUH8xP3FYVePReohKA9zTcjW27iPXqDE3dBE",
            },
        ],
    },
    {
        "class": ElectrumV2Standard,
        "seed": b"fffddf6e1df839ce35f79d2ce35f10873644d9bdc5a32dddbbc221812e270065644a1ea06e37b8796b16edf38c3c410d55c2c10e3947ad683b1841ad8a0ffa18",
        "master_pub_key": "3691f09681b3c98757492018efa2737238309be00fbe4824f5325feb4db6ec0b86cdfac4c882098a2d7bc7fb9f07cc4e58c753a09f570b88c902700993747a08",
        "master_priv_key": "Ky5CPaKtq1xt2tjYWacfhtPtL8RR42Cp6pBk8Src4xXvSVFBCFuc",
        "addresses": [
            {
                "address": "1EerftvFRRRkS279CnWyPKw6x5vxRDa5VW",
                "priv_key": "L4eC991EVrUexioWmAFggf23C9hY2tmiDxKtzU3n9TcHt5dNJyuk",
            },
            {
                "address": "1GPYPF5GkeexJgnbuALecn8sMiEKkJieBW",
                "priv_key": "L53AkfvmHggHPDpwjuu8EfAqqSaHxTDV7q4GA53jsz3gzT8s5YPR",
            },
            {
                "address": "15bzjDxjn2ZrisUKKutXweVah3Ec2d2pd7",
                "priv_key": "L2aaTU12z1pTud2RKSHhbVWkQaqAKxP6mvwYmFeAhLRTWN4aMhVi",
            },
            {
                "address": "1CbUAWMnwqs3jGLeXRd9v2u3ttHgN7m8Ki",
                "priv_key": "L4oB8txBvNbewoFbXEjWaTcXPsAy34eBPFMUNQQ4t5RFU1165Vwu",
            },
            {
                "address": "1LQQj91tCHbd5VEhEWyTjHEivw6GBT8fwS",
                "priv_key": "KwieQ4APqmV3TS9amgw4ZDJ1mC5uaSBQrPddDz4PR6jpHBSozwks",
            },
        ],
    },
    {
        "class": ElectrumV2Segwit,
        "seed": b"774e6f1d3392014872b1d293081de124dec2c890e31d38319f6280328321dc17c0786448a94a47a3e90b97d74925c2c1403333a137ed4bf9cdc5342b9c4d967c",
        "master_pub_key": "0e488158190a04057292fcb2916432031acdc95a68c4196edeff1d7b7b6f6045c0267ed1d783ff05dc9d4d34f0fa0c752e75c98bfd0f3f1e67bec88b7dba956e",
        "master_priv_key": "KzC5mk7nAVadWE7sc8uMKFt6FjQSo9k8xdB6B2kap7pp4GxSFTrX",
        "addresses": [
            {
                "address": "bc1q3jgz0mg9qgdz0rhnur8kky3ed2l870xk6nn8rh",
                "priv_key": "L2cmqdJsHxRrE4p4GQs4LNavJpBbhfWyhhwKXtND7SDJMhC1yaPY",
            },
            {
                "address": "bc1qd8r3cf0g5hfkmw4ys5j5tsfv4gugtjfs7wds58",
                "priv_key": "KzgTFzLUzcB6vqw4rBZj2dtC69Nj3NQDr3PfirCs2pHtxz5TENi5",
            },
            {
                "address": "bc1qym6rtyphwz0tdq9dhzskzfmv8hqrd4pdjlsr06",
                "priv_key": "L52xWTwu3fcr98Ra7MSyaoNLXjc19p1iTVC9GKxEdaYFYxivzNka",
            },
            {
                "address": "bc1q2hxyxcxptpjhe4ve6mxk6r6qtkda4tu5khwq3h",
                "priv_key": "KynErkDcH5zV5MYiZPRXZ3bhrme13Dju1iU33t7BWHJM4yeejxmM",
            },
            {
                "address": "bc1quwlk8dp32g0l97dy8apugg00p288pm7vkw4npz",
                "priv_key": "Kz5pvBim97qioZkkN5kQNeHReiBWsxjVrnrv9gwkkA2UP8fEMnQR",
            },
        ],
    },
    {
        "class": ElectrumV2Segwit,
        "seed": b"00219651692bc515f5d3bb92325d117d4c6a9d9084f1df94be6301bcdbe4d068a7711a0052b03c3b9926286487aa12cefc26832bd554dd0fed61e8ee0b72c272",
        "master_pub_key": "f18e42c0b626428905ca89cd052307d86d8fa3d47ae9f2b9bf51171b4b12a9f654b01c1cfed95c2e4e905ab072ddd56459c4c00286c6a63d27305f900a1430e7",
        "master_priv_key": "L58rNyGZ4PNueQ8K8jYPK9pHY7LG2SjxPoTRh3BJQg6CnSErE95Z",
        "addresses": [
            {
                "address": "bc1q5q3k25dmfx6mfj2q8srf2gkcvjy6fxcnjh93se",
                "priv_key": "KxksyrQzSUedqvdxzfcALhUUmEVAcrS266DYpRCUgSVsAghXnaxL",
            },
            {
                "address": "bc1q230ydw9nm297xpyu35md5xk6cqzuewev32xln8",
                "priv_key": "KwTu9NPxsSuMrEuGov6N9rSAFk5QugntKTg1CQeCJAW7kmbibVUF",
            },
            {
                "address": "bc1qgvcvjxhj9d87vx5zhcu5j8sgq5ge9f2sn2rn2p",
                "priv_key": "KzA939hMo1Y21rYYcQApdfry4hdzakG48F2gveW6CfnD9thG6Lr7",
            },
            {
                "address": "bc1qn8ed88mvw2ffgnvk0gvz8005r7cyaktnmfrz2p",
                "priv_key": "KxVjkbKx7VnpSyTjq2o3wkQ5oi9k4an2VfZwJR86kcY22KV119Tz",
            },
            {
                "address": "bc1qhvew455a8h7lea259nzen53vwcmt647pd6g89n",
                "priv_key": "Kyx3EdBQnzT99EsEPp6asqS3CKh8zDFoJpcXUVqqMacwtTuqmYHK",
            },
        ],
    },
]


#
# Tests
#
class ElectrumV2Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            seed_bytes = binascii.unhexlify(test["seed"])
            # Test both FromSeed and direct construction
            self.__test_wallet(test["class"].FromSeed(seed_bytes), test)
            self.__test_wallet(test["class"](Bip32Slip10Secp256k1.FromSeed(seed_bytes)), test)

    # Test invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, ElectrumV2Standard, Bip32Slip10Ed25519.FromSeed(TEST_SEED))
        self.assertRaises(TypeError, ElectrumV2Segwit, Bip32Slip10Ed25519.FromSeed(TEST_SEED))
        # Not a master key
        self.assertRaises(ValueError, ElectrumV2Segwit, Bip32Slip10Secp256k1.FromSeed(TEST_SEED).DerivePath("m/0"))

    # Test wallet
    def __test_wallet(self, electrum_v2, test):
        self.assertFalse(electrum_v2.IsPublicOnly())
        self.assertTrue(isinstance(electrum_v2.Bip32Object(), Bip32Slip10Secp256k1))
        self.assertTrue(isinstance(electrum_v2.MasterPublicKey(), Bip32PublicKey))
        self.assertTrue(isinstance(electrum_v2.MasterPrivateKey(), Bip32PrivateKey))

        self.assertEqual(test["master_pub_key"], electrum_v2.MasterPublicKey().RawUncompressed().ToHex()[2:])
        self.assertEqual(test["master_priv_key"], self.__priv_to_wif(electrum_v2.MasterPrivateKey()))

        for i, test_addr in enumerate(test["addresses"]):
            self.assertTrue(isinstance(electrum_v2.GetPublicKey(0, i), Bip32PublicKey))
            self.assertTrue(isinstance(electrum_v2.GetPrivateKey(0, i), Bip32PrivateKey))

            self.assertEqual(test_addr["address"], electrum_v2.GetAddress(0, i))
            self.assertEqual(test_addr["priv_key"], self.__priv_to_wif(electrum_v2.GetPrivateKey(0, i)))

    # Encode private key to WIF
    @staticmethod
    def __priv_to_wif(priv_key):
        return WifEncoder.Encode(priv_key.KeyObject(),
                                 CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"))
