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
from bip_utils import Bip44, Bip44Coins, Bip44Chains


# Some seeds randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master" :  "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
            "account" :
                {
                    "ex_pub"  : "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
                    "ex_priv" : "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "xpub6ELHKXNimKbxMCytPh7EdC2QXx46T9qLDJWGnTraz1H9kMMFdcduoU69wh9cxP12wDxqAAfbaESWGYt5rREsX1J8iR2TEunvzvddduAPYcY",
                    "ex_priv" : "xprvA1Lvv1qpvx3f8iuRHfaEG45fyvDc3h7Ur5afz5SyRfkAsZ2765KfFfmg6Q9oEJDgf4UdYHphzzJybLykZfznUMKL2KNUU8pLRQgstN5kmFe",
                },
            "addresses" :
                [
                    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                    "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP",
                    "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb",
                    "1MVGa13XFvvpKGZdX389iU8b3qwtmAyrsJ",
                    "1Gka4JdwhLxRwXaC6oLNH4YuEogeeSwqW7",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"306e596bf6a09a53722796f611b33523a1ab43e408cd2af67f98f4b40366a588f264c50f38e85b67c8243621b1c790e4419ab51224873f10bd333aa6318ffb01",
            "ex_master" :  "xprv9s21ZrQH143K3ioXN1NmmgahervNySkx7B5RJBSyaGkvAHdHkU529Z46WQMA195L6YQFVQpq1z5FQB2v2vqdNWKmK5dTDAbzTHbqiDCBbtM",
            "account" :
                {
                    "ex_pub"  : "xpub6CDeHx5g8UQ7bHNkrYLwbAqtUfnKvLixNnA2EiZYEWH4Ax48NJ8MLEhmEjQF75hSRWYo95ufsjxXLJEjSCSThCqRaQQEukGbdrwqHG9yEv3",
                    "ex_priv" : "xprv9yEHtSYnJ6qpNoJHkWowE2u9vdwqWt171ZERSL9vgAk5J9iypkp6nSPHPRuzkJSPgR1YbKED1YGhDPL5VPxvsrk3ahgk8kUyDevzmu3LoHb",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "xpub6F8rCxd5xYPjhuc3eeAAVgLf1ftwjdrBnNfX264RadjSnDDCG14o7gekEztB48P8UreEr17CxTWVFkqETfsahXQKPuvPBX9vQs3ux24K8A9",
                    "ex_priv" : "xprvA29VoT6C8AqSVRXaYcdA8YPvTe4TLB8LR9jvDhep2JCTuQt3iTkYZtLGPmS3CQtyVyVDw449QQWbVJJsw89aQKNsJiMkdKVdh4CMritLKok",
                },
            "addresses" :
                [
                    "1QLbrXrSezVGv3zJksdztkVdNQCmyhQKLh",
                    "1oVc8sjWDMdutBBmNNjzcS29W2Rc5xyv1",
                    "19dWrrFSKfgtWYLCLQa2PYqTLDQ3gywkN5",
                    "14v7aXVZ2QfBH69go1FkX683eiwKTjjjmN",
                    "1FHosmBRCPNmq7dSDZf3F22EHF9Gdi86Jm",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"1bad872e179da9f8f5089d84a7b4c5a2bf501623070302f6481ad088fe6b27be538d99151f9526f06f09f7bca6dfcd74aea2920f1d9fe5e44392c6bcf81389fd",
            "ex_master" :  "xprv9s21ZrQH143K4bhdEo2Qn25iQb5vsrnE9cjDSVxYBQ5etiMK3jDLDNJR7yxa4qFYiGDjyCso7sbFLyMn9L5QNXqiCQQfUwDZP284hPWBj26",
            "account" :
                {
                    "ex_pub"  : "xpub6CiqgTRFHN9Dkuz32tobfCQTuYd5pm5QerQFpjguseHfYDjdCCYJYYDiPHjMF79ifzweZ4Y22USU1w4FhYo9EUbKX9zCEztgQK9hjmAu1Cr",
                    "ex_priv" : "xprv9yjVGwtMSzavYRuZvsGbJ4TjMWnbRJMZHdUf2MHJKJkgfRQUefE3zjuEY1Dw8MNJFAoXV6SSzvdTMrFmzrhJf6EgiCig9W6oJcoPMHi2WKr",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "xpub6F6hcHUJ2vVxrLUV4zisPKvVRpYvnDYcB4zKuNRh9zmNpgArXszwNsM5MKCZJdfU1cGp7rYLJ38w58GwgHYQfMSa6yxA9zoPnCnbXrkJU9Q",
                    "ex_priv" : "xprvA27MCmwQCYwfdrQ1xyBs2ByksniSNkpkor4j6z25bfEPwsqhzLggq52bVzd8MYjQKKVp8UvHqmtEjjZpmFAFQQxV6avzJ5PVPvnqcPy2YMt",
                },
            "addresses" :
                [
                    "199qCZxNj8Avh2bX8zZ8oHuvzLxf79HDmu",
                    "16WtfijERPosmUcVVfJAHfqLdTDcBQLNtn",
                    "1GPAFTSZGkardWuLEmr8gigng2RSPNXfmF",
                    "1LyGG7FvgxTtpy5JkmP7sUdhkUdKq8s7ct",
                    "128ghyy4NJ3kKz14haJky1PoiF5ZVcAzwP",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN_TESTNET,
            "seed"      : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master" :  "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd",
            "account" :
                {
                    "ex_pub"  : "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba",
                    "ex_priv" : "tprv8fPDJN9UQqg6pFsQsrVxTwHZmXLvHpfGGcsCA9rtnatUgVtBKxhtFeqiyaYKSWydunKpjhvgJf6PwTwgirwuCbFq8YKgpQiaVJf3JCrNmkR",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "tpubDEQBfiy13hMZzGT4NWqNnaSWwVqYQ58kuu2pDYjkrf8F6DLKAprm8c65Pyh7PrzodXHtJuEXFu5yf6JbvYaL8rz7v28zapwbuzZzr7z4UvR",
                    "ex_priv" : "tprv8hi9XJvkuKfu6oRGUsAnPAnQNUKcEjwrLbS2w2hTSPKrFj5YYS3Ax7UDDrZZHd4PSnPLW5whNxAXTW5bBrSNiSD1LUeg9n4j5sdGRJsZZwP",
                },
            "addresses" :
                [
                    "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
                    "mzpbWabUQm1w8ijuJnAof5eiSTep27deVH",
                    "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp",
                    "mpW3iVi2Td1vqDK8Nfie29ddZXf9spmZkX",
                    "n2BMo5arHDyAK2CM8c56eoEd18uEkKnRLC",
                ],
        },
    ]


#
# Tests
#
class Bip44Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            is_testnet = test["coin"] == Bip44Coins.BITCOIN_TESTNET

            # Create from seed
            bip_obj_ctx = Bip44.FromSeed(binascii.unhexlify(test["seed"]), is_testnet)
            # Test master key
            self.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey())

            # Derive account
            bip_obj_ctx = bip_obj_ctx.Purpose().Coin(test["coin"]).Account(0)
            # Test account keys
            self.assertEqual(test["account"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey())

            # Derive external chain
            bip_obj_ctx = bip_obj_ctx.Chain(Bip44Chains.CHAIN_EXT)
            # Test external chain keys
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey())

            # Test external chain addresses
            for i in range(len(test["addresses"])):
                self.assertEqual(test["addresses"][i], bip_obj_ctx.AddressIndex(i).Address())

    # Test wrong path derivations
    def test_wrong_derivations(self):
        seed = b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

        # Create all the derivations
        bip_obj_mst   = Bip44.FromSeed(binascii.unhexlify(seed))
        bip_obj_prp   = bip_obj_mst.Purpose()
        bip_obj_coin  = bip_obj_prp.Coin(Bip44Coins.BITCOIN)
        bip_obj_acc   = bip_obj_coin.Account(0)
        bip_obj_chain = bip_obj_acc.Chain(Bip44Chains.CHAIN_EXT)
        bip_obj_addr  = bip_obj_chain.AddressIndex(0)

        # Wrong derivation from master
        self.assertRaises(RuntimeError, bip_obj_mst.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_mst.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_mst.Chain       , Bip44Chains.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_mst.AddressIndex, 0)
        # Wrong derivation from purpose
        self.assertRaises(RuntimeError, bip_obj_prp.Purpose)
        self.assertRaises(RuntimeError, bip_obj_prp.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_prp.Chain       , Bip44Chains.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_prp.AddressIndex, 0)
        # Wrong derivation from coin
        self.assertRaises(RuntimeError, bip_obj_coin.Purpose)
        self.assertRaises(RuntimeError, bip_obj_coin.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_coin.Chain       , Bip44Chains.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_coin.AddressIndex, 0)
        # Wrong derivation from account
        self.assertRaises(RuntimeError, bip_obj_acc.Purpose)
        self.assertRaises(RuntimeError, bip_obj_acc.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_acc.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_acc.AddressIndex, 0)
        # Wrong derivation from chain
        self.assertRaises(RuntimeError, bip_obj_chain.Purpose)
        self.assertRaises(RuntimeError, bip_obj_chain.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_chain.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_chain.Chain       , Bip44Chains.CHAIN_EXT)
        # Wrong derivation from address index
        self.assertRaises(RuntimeError, bip_obj_addr.Purpose)
        self.assertRaises(RuntimeError, bip_obj_addr.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_addr.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_addr.Chain       , Bip44Chains.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_addr.AddressIndex, 0)


# Run test if executed
if __name__ == "__main__":
    unittest.main()
