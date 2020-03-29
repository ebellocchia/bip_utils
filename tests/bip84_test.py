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
from bip_utils import Bip84, Bip44Coins, Bip44Chains


# Some seeds randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "coin"   : Bip44Coins.BITCOIN,
            "seed"   : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "master" :  "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
            "account" :
                {
                    "ex_pub"  : "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
                    "ex_priv" : "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "zpub6u4KbU8TSgNuZSxzv7HaGq5Tk361gMHdZxnM4UYuwzg5CMLcNytzhobitV4Zq6vWtWHpG9QijsigkxAzXvQWyLRfLq1L7VxPP1tky1hPfD4",
                    "ex_priv" : "zprvAg4yBxbZcJpcLxtXp5kZuh8jC1FXGtZnCjrkG69JPf96KZ1TqSakA1HF3EZkNjt9yC4CTjm7txs4sRD9EoHLgDqwhUE6s1yD9nY4BCNN4hw",
                },
            "addresses" :
                [
                    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                    "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z",
                    "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
                    "bc1qm97vqzgj934vnaq9s53ynkyf9dgr05rargr04n",
                ],
        },
        {
            "coin"   : Bip44Coins.BITCOIN,
            "seed"   : b"306e596bf6a09a53722796f611b33523a1ab43e408cd2af67f98f4b40366a588f264c50f38e85b67c8243621b1c790e4419ab51224873f10bd333aa6318ffb01",
            "master" :  "zprvAWgYBBk7JR8GkKBm2ix2BrmhzoDGrgjwwQ7rryEkLHWgGVFkFnQ9PgNNYpGKzxPAupdrzN1wwJnMAkG3UKfexygy3m2JNzExzjj8VKUy5c4",
            "account" :
                {
                    "ex_pub"  : "zpub6qjvNWwXNVMbZ4fC3XmS6MVEQz27RzB7NiiBPgMYX4bfBKa91GbHTSKL2zfkYdWcjQE9s2CG2Ze9S3f3ahK5k3mg4XEWZJEsS974XgDYmnr",
                    "ex_priv" : "zprvAckZy1QdY7oJLaaiwWERjDYVrxBd2XTG1VnabHwvxj4gJXEzTjH2udzrBk8Zao8pZbL8K49MaXHbDiYSTwBFELw4XeoXWvDjSQZuVgNn4SJ",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "zpub6sxwqZPbjApkni1EoCw1tms29Z2EPGL1ZnV6184UyZPtCwNy99C5HS8TD6H38NFNCyQkvzxK759KXyo9oUesDNEEpi1VSqTEf9aEMR6qRk4",
                    "ex_priv" : "zprvAeybS3rhtoGTaDvmhBQ1XdvHbXBjyocACZZVCjesRDruL93pbbspjdoyMohiHrK3UqeBtLofzsFnCJypidieJ1A78wKyRpLBVtVk2N1FmXB",
                },
            "addresses" :
                [
                    "bc1q553ay4mycq58yvzef86nes093feka2e0y3x29t",
                    "bc1qcr0p0vq6gzqm23wrvkp2gl49czqx7lvlhs867n",
                    "bc1qfsxj3tq7gmc7l0ejmt3z743d6z8czcvtwepz4a",
                    "bc1q3xa5qtryj6pd9vzkmczhdqa53zxznu0dyl6ezw",
                    "bc1q48ezuc263lwlrmf2lfjzknxeve7a79hqnu6s8w",
                ],
        },
        {
            "coin"   : Bip44Coins.BITCOIN,
            "seed"   : b"1bad872e179da9f8f5089d84a7b4c5a2bf501623070302f6481ad088fe6b27be538d99151f9526f06f09f7bca6dfcd74aea2920f1d9fe5e44392c6bcf81389fd",
            "master" :  "zprvAWgYBBk7JR8GmC5ruWbfCCGikXNpm6mDyqmf1HkJwQqQzuymZ3YTTVchAPsk4eZPXYTMUA4v3CJM7YauaiuRy1Cuw5oWekrXvUFMUUgBWEg",
            "account" :
                {
                    "ex_pub"  : "zpub6qXE22uQVDapQ5zM62qhezAAaP3MUMedNn9at7cRFquoJcyJpfQmiR3zTzSKZkvBgjJJkQzLDNpHu3pZHng6kLxG8k1uPwb3FfSpnyymMye",
                    "ex_priv" : "zprvAcXscXNWer2XBbusz1JhHrDS2MCs4tvn1ZDz5jCohWNpRpeAH86XAcjWcgW84iXKkigEDbR7ZGr7uWKpc9wduHPiBCrUbDFXZUFsiU1f88R",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "zpub6syfwxJbTeVao115xNXSqxGcvhoW5K8LXxZQdMV9nVybsK1oXjiqVsxea54akoqaoqyTktkh6oGakwAhbJCxLwSR3oqXUxNUiqcdg57hxcg",
                    "ex_priv" : "zprvAezKYSmhdGwHaWvcrLzSUpKtNfy1frQVAjdopy5YEASczWgezCQax5eAip8RRKjgkNarCqyVoMZF5q5Xs88vULxgVXrAt4Vwu8ChrFa8gbb",
                },
            "addresses" :
                [
                    "bc1qs4qe0egpu4vu08pgta97rsxqcmc9sn5lpn74h8",
                    "bc1qn59e0fhceggrd3e2a6gyq7fn82tgvedezemtel",
                    "bc1qucfsfrsneph3qjljcxpgl2cc3a4gyg2v0fh95e",
                    "bc1qdxuahtwc9eg80g7fmn84qxrw2p5mehgpjx9s2e",
                    "bc1qwfax0g59dzkzs952xruyw92jkec0puxcljd0eq",
                ],
        },
        {
            "coin"   : Bip44Coins.BITCOIN_TESTNET,
            "seed"   : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "master" : "vprv9DMUxX4ShgxMLfvb8sFY4xFFKyTibwTfoydH3beVutr1L3bWHhRn3f2SqSo3vdUacd6QuuUxmN8BYoGhX2J4okpwCMh4nwdq9EqbdGgioRF",
            "account" :
                {
                    "ex_pub"  : "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc",
                    "ex_priv" : "vprv9K7GLAaERuM58PVvbk1sMo7wzVCoPwzZpVXLRBmum93gL5pSqQCAAvZjtmz93nnnYMr9i2FwG2fqrwYLRgJmDDwFjGiamGsbRMJ5Y6siJ8H",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "vpub5baxyhXRwCQ1N4KuQfdVSfnYahk6HDRCqDhQJjgSbxo8SzP5ghgHugxZuQ9TpfGC2oTBYdVi8thxMGhqjcVbNPMBNRKMX9x1PZW4LXNyq7q",
                    "ex_priv" : "vprv9NbcaBzY6pqi9aFSJe6V5Xqp2fubskhMTzmoWMGq3dG9aC3w9AN3Mte646s59AnZaiAgg2rAgxPYusyEMm2YADoaa5nRaGoExuVVZGc7HCC",
                },
            "addresses" :
                [
                    "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
                    "tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97",
                    "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
                    "tb1qynpgs6wap6h9uvy7j0xlesew2w82qn038zm5km",
                    "tb1q677973lw0w796gttpy52f296jqaaksz0555pg2",
                ],
        },
    ]

#
# Tests
#
class Bip84Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            is_testnet = test["coin"] == Bip44Coins.BITCOIN_TESTNET

            # Create from seed
            bip_obj_ctx = Bip84.FromSeed(binascii.unhexlify(test["seed"]), is_testnet)
            # Test master key
            self.assertEqual(test["master"], bip_obj_ctx.PrivateKey())

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
        bip_obj_mst   = Bip84.FromSeed(binascii.unhexlify(seed))
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
