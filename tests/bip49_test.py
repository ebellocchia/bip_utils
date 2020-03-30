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
from bip_utils import Bip49, Bip44Coins, Bip44Changes


# Some seeds randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master" :  "yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E",
            "account" :
                {
                    "ex_pub"  : "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
                    "ex_priv" : "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "ypub6Ynvx7RLNYgWzFGM8aeU43hFNjTh7u5Grrup7Ryu2nKZ1Y8FWKaJZXiUrkJSnMmGVNBoVH1DNDtQ32tR4YFDRSpSUXjjvsiMnCvoPHVWXJP",
                    "ex_priv" : "yprvAKoaYbtSYB8DmmBt2Z7TgukWphdCiSMRVdzDK3aHUSna8jo6xnG41jQ11ToPk4SQnE5sau6CYK4od9fyz53mK7huW4JskyMMEmixACuyhhr",
                },
            "addresses" :
                [
                    "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
                    "3LtMnn87fqUeHBUG414p9CWwnoV6E2pNKS",
                    "3B4cvWGR8X6Xs8nvTxVUoMJV77E4f7oaia",
                    "38CahkVftQneLonbWtfWxiiaT2fdnzsEAN",
                    "37mbeJptxfQC6SNNLJ9a8efCY4BwBh5Kak",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"306e596bf6a09a53722796f611b33523a1ab43e408cd2af67f98f4b40366a588f264c50f38e85b67c8243621b1c790e4419ab51224873f10bd333aa6318ffb01",
            "ex_master" :  "yprvABrGsX5C9janu1zeCNAPymgCpq4pv4kT2Hbe5aLrxH8oDPSX18EamciEXcJk13jFWBX4EtRPUeRoHTeUkdFeAk1NBRKso5RUj1fV6nN5xvS",
            "account" :
                {
                    "ex_pub"  : "ypub6WsMVpXGGQSKKpCq2gi2KdHFTmrxnx1UbuzXm33e56Zqq26M1MgobUZXq5brmcPSkPFtqZG2FT4wpxuUtqssHjmAZ957k1cne4pCtASnC2D",
                    "ex_priv" : "yprvAHt16JzNS2t27L8MvfB1xVLWuk2UPVHdEh4vxee2Wm2rxDmCTpNZ3gF3yngcgtYUjD8cz5Xfu3j53Jkz6CwGcNMXQU3SCm5ACCYkQfMDZ2t",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "ypub6ZbH7bCvi8SkeWHYFB51otUFjqBv9NYMVte5APK5wgfEnfbu5kE7HpHDxSzosiA7KDBzucxcZffFy1dApKQHVkNXHiV2zcb9s1FhiuSCKPu",
                    "ex_priv" : "yprvALbvi5g2sktTS2D599Y1SkXXBoMRjupW8fiUMzuUPM8FusGkYCurk1xk7BUBMihx4corRGx7X2qcLAZ2zHHn2NCnng7UdJLHGqEBn7t6xsQ",
                },
            "addresses" :
                [
                    "39HPGDABwg9mkoTDxvuBn1eDcjDUqGMcPN",
                    "34bbHuTJdCS9DK6wnEHeSpFZHdjevov8RH",
                    "3BEorFdeeDLtepvLPExaYGDxSstBbbx7Zp",
                    "3KPbrKVwM9e3uzqGFEnPqCafLP7gkNwgjC",
                    "3Ke8N2Bt5TdiuAhwd2ignMi1ZU9WFuZAUD",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN,
            "seed"      : b"1bad872e179da9f8f5089d84a7b4c5a2bf501623070302f6481ad088fe6b27be538d99151f9526f06f09f7bca6dfcd74aea2920f1d9fe5e44392c6bcf81389fd",
            "ex_master" :  "yprvABrGsX5C9januttk59p2z7BDaZENpUmj4jFSDtrRZQTXwpAYJPNtqRxZ9BvA4juU7uLYigUMaXwoEFyLs2VRAmXK4k764r33ekBi5yP83Kp",
            "account" :
                {
                    "ex_pub"  : "ypub6Xm6aeYM4Wi1sL1GfXdRAyd1HxHJBkuA11epKWrQznBXnyUy8uqY6QKChc1nBPdK2zA74hEo9BEmiKqCVvywfdiJxVfsufEzWJTvbZtd8wG",
                    "ex_priv" : "yprvAJmkB91TE99ieqvoZW6QoqgGjvSonJBJdnjDX8SoSSeYvB9pbNXHYbzirHxBzSR7eY8ULtqkr4eXkCZ3od2BMpVjCT4c5xGNvHPRxLNraaQ",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "ypub6YRiK1asr23uGpALuUojU6NXXQqTGHAmakMnu9T93zHJxetRBvx72VEbEPpjPJT9JcbQpxbxzQrfJKPXK6Xcr6C3nMfAL9mrwUsnRcT7dDN",
                    "ex_priv" : "yprvAKSMuW3z1eVc4L5soTGj6xRnyNzxrpSvDXSC6m3XVekL5rZGePdrUgv7P5hpM5zK1Ey3Ry7GRMakdS89pYcLWMVDSDVpgmyc3DktSATEP3Q",
                },
            "addresses" :
                [
                    "3E8F1PzAfPZqeiofY5yAcCB9gGgBZpmLno",
                    "38xSfHtq7dNpj36a7wuYUcZgLz3eGbHcfd",
                    "3Ab7tsp8qDV89j5NLukPoHdXwziHGAEDnB",
                    "3QVsfA5Z5fPcxVgBpZGR93WYGufvGHjcFU",
                    "3GnoLRV3H4AvoWaf9iKY14J2EUr7DoTEbj",
                ],
        },
        {
            "coin"      : Bip44Coins.BITCOIN_TESTNET,
            "seed"      : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master" :  "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd",
            "account" :
                {
                    "ex_pub"  : "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY",
                    "ex_priv" : "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "upub5F7X3ZAt1HsUyFLTFU9vhKeGULy77aDoJFhscvGBV91tm2mzQ5egFGpeP4nGskwERwbU48g14qREqXJ388X8XBiaLm7PWwk3S45Fe3WAvdK",
                    "ex_priv" : "uprv928Ae3dzAvKBkmFz9ScvLBhXvK8ci7Vww2nGpXrZvoUutESqrYLRhUWAXpK5acXh517npKuCpJ7NXaoWnLs1dLB9w3MHe3KNUm7hPENqMzt",
                },
            "addresses" :
                [
                    "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
                    "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
                    "2N9LKph9TKtv1WLDfaUJp4D8EKwsyASYnGX",
                    "2MyVXDzGJgATSdkhKHWvStpBoGEZb1fwjha",
                    "2MuKeQzUHhUQWUZgx5AuNWoQ7YWx6vsXxrv",
                ],
        },
    ]


#
# Tests
#
class Bip49Tests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction
    def test_vector_from_seed(self):
        for test in TEST_VECTOR:
            is_testnet = test["coin"] == Bip44Coins.BITCOIN_TESTNET

            # Create from seed
            bip_obj_ctx = Bip49.FromSeed(binascii.unhexlify(test["seed"]), is_testnet)
            # Test master key
            self.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey())

            # Derive account
            bip_obj_ctx = bip_obj_ctx.Purpose().Coin(test["coin"]).Account(0)
            # Test account keys
            self.assertEqual(test["account"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey())

            # Derive external chain
            bip_obj_ctx = bip_obj_ctx.Change(Bip44Changes.CHAIN_EXT)
            # Test external chain keys
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey())

            # Test external chain addresses
            for i in range(len(test["addresses"])):
                self.assertEqual(test["addresses"][i], bip_obj_ctx.AddressIndex(i).Address())

    # Run all tests in test vector using FromExtendedKey for construction
    def test_vector_from_exkey(self):
        for test in TEST_VECTOR:
            # Create from master key
            bip_obj_ctx = Bip49.FromExtendedKey(test["ex_master"])
            # Test master key
            self.assertTrue(bip_obj_ctx.IsMasterLevel())
            self.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey())

            # Create from account key
            bip_obj_ctx = Bip49.FromExtendedKey(test["account"]["ex_priv"])
            # Test account keys
            self.assertTrue(bip_obj_ctx.IsAccountLevel())
            self.assertEqual(test["account"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey())

            # Create from change key
            bip_obj_ctx = Bip49.FromExtendedKey(test["chain_ext"]["ex_priv"])
            # Test external change keys
            self.assertTrue(bip_obj_ctx.IsChangeLevel())
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey())
            self.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey())

    # Test wrong path derivations
    def test_wrong_derivations(self):
        seed_bytes = b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

        # Create all the derivations
        bip_obj_mst    = Bip49.FromSeed(binascii.unhexlify(seed_bytes))
        bip_obj_prp    = bip_obj_mst.Purpose()
        bip_obj_coin   = bip_obj_prp.Coin(Bip44Coins.BITCOIN)
        bip_obj_acc    = bip_obj_coin.Account(0)
        bip_obj_change = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip_obj_addr   = bip_obj_change.AddressIndex(0)

        # Wrong derivation from master
        self.assertRaises(RuntimeError, bip_obj_mst.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_mst.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_mst.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_mst.AddressIndex, 0)
        # Wrong derivation from purpose
        self.assertRaises(RuntimeError, bip_obj_prp.Purpose)
        self.assertRaises(RuntimeError, bip_obj_prp.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_prp.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_prp.AddressIndex, 0)
        # Wrong derivation from coin
        self.assertRaises(RuntimeError, bip_obj_coin.Purpose)
        self.assertRaises(RuntimeError, bip_obj_coin.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_coin.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_coin.AddressIndex, 0)
        # Wrong derivation from account
        self.assertRaises(RuntimeError, bip_obj_acc.Purpose)
        self.assertRaises(RuntimeError, bip_obj_acc.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_acc.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_acc.AddressIndex, 0)
        # Wrong derivation from chain
        self.assertRaises(RuntimeError, bip_obj_change.Purpose)
        self.assertRaises(RuntimeError, bip_obj_change.Coin   , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_change.Account, 0)
        self.assertRaises(RuntimeError, bip_obj_change.Change , Bip44Changes.CHAIN_EXT)
        # Wrong derivation from address index
        self.assertRaises(RuntimeError, bip_obj_addr.Purpose)
        self.assertRaises(RuntimeError, bip_obj_addr.Coin        , Bip44Coins.BITCOIN)
        self.assertRaises(RuntimeError, bip_obj_addr.Account     , 0)
        self.assertRaises(RuntimeError, bip_obj_addr.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(RuntimeError, bip_obj_addr.AddressIndex, 0)


# Run test if executed
if __name__ == "__main__":
    unittest.main()
