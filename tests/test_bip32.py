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
from bip_utils import Bip32, Bip32KeyError, Bip32Utils

# Tests from BIP32 page
TEST_VECT_BIP32 = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "master": {
            "ex_pub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            "ex_priv": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32Utils.HardenIndex(0),
                "ex_pub": "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "ex_priv": "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "ex_priv": "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32Utils.HardenIndex(2),
                "ex_pub": "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "ex_priv": "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "ex_priv": "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                "ex_priv": "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "master": {
            "ex_pub": "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            "ex_priv": "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "ex_priv": "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32Utils.HardenIndex(2147483647),
                "ex_pub": "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "ex_priv": "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "ex_priv": "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32Utils.HardenIndex(2147483646),
                "ex_pub": "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "ex_priv": "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                "ex_priv": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
            },
        ],
    },
    {
        "seed": b"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "master": {
            "ex_pub": "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            "ex_priv": "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32Utils.HardenIndex(0),
                "ex_pub": "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                "ex_priv": "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
            },
        ],
    },
]

# Tests for public derivation
TEST_VECT_PUBLIC_DER = {
    "ex_priv": "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
    "ex_pub": "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "ex_pub": "xpub68jrRzQfUmwSaf5Y37Yd5uwfnMRxiR14M3HBonDr91GB7GKEh7R9Mvu2UeCtbASfXZ9FdNo9FwFx6a37HNXUDiXVQFXuadXmevRBa3y7rL8",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6APw4JtXQKMKHbqzD7pxeiGcArZVSNuUcbcKvcoQ3JxPjdCYaap6BuVW4HRSmV4gwSv4CzC5Cjsp9kesdHUFHtpz42Bg4UoiJ1KsJQx9AuH",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32Utils.HardenIndex(0),
        },
    ],
}

# Tests for invalid seeds
TEST_VECT_SEED_ERR = [
    b"000102030405060708090a0b0c0d0e",
    b"000102030405060708090a0b0c0d",
]

# Tests for invalid extended key
TEST_VECT_EX_KEY_ERR = [
    # Private keys with invalid lengths (generated on purpose to have a correct checksum)
    "DeaWiRvhTUWHmRFa63ZawWQy57DX4NvP62TfD46boXurKLAgyUEp5Xz59LLRSa4sse2nscJCmFC4DvmScVSuJSxfQAzFhxDc4RV85PtjgAwLMX",
    "5FQFKc7mTW13jdERCczZfzcHum9pTkjqVdP6HZCVtfC2YAjAT8RnDG6Lmo583qUQx2toUpuxyEJFVgAp725tEfbUJqXEA1WCgm8Qm4BPft8otyZpr",
    # Private key with invalid net version
    "yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E",
    # Private key with invalid secret byte (0x01 instead of 0x00, generated on purpose)
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnListey6gETHL1FYgFnbGTHGh6bsXjp3w31igA2CuxhgLyGu6pvL45",
    # Invalid private key (secret is zero)
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisrXZJziEEC1DUnKroSfeGxPp2YKsFRobQpLPsPTCU64kGZdiNbk",
    # Invalid master key (fingerprint is not valid)
    "xprv9s21ZrQZgP7FPptNcV6ZuWeytnfAsNFoPXFUTMDdUQpc44ZhfkDAnctGeUuywWTKXEFwLFGRPGd9WcjbTDdjKU25eRw5REDTVxfiAxZFhrV",
    # Invalid master key (index is not zero)
    "xprv9s21ZrQH143K5p8oLYasVfWDcfK9E5HPajvc6vEmTG592KSs8jk4fb3vA6ZoueJM4oi7xTrbbfU5MyTPRLFPbXLr3TZjQw4rXFQ7v1sk7C4",
    # Invalid public key (it's a private key with public net version, generated on purpose)
    "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCj3rW1cw1qdn2KJo1MSajvp3cr5ceA5nJT3QHp65rcYr8AUbzLPh",
]


#
# Bip32 tests
#
class Bip32Tests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        for test in TEST_VECT_BIP32:
            # Create from seed
            bip32_ctx = Bip32.FromSeed(binascii.unhexlify(test["seed"]))
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for chain in test["der_paths"]:
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(chain["index"])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        for test in TEST_VECT_BIP32:
            # Create from seed
            bip32_ctx = Bip32.FromSeed(binascii.unhexlify(test["seed"]))
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for chain in test["der_paths"]:
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(chain["path"][2:])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        for test in TEST_VECT_BIP32:
            # Create from seed
            bip32_ctx = Bip32.FromSeedAndPath(binascii.unhexlify(test["seed"]), "m")
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for chain in test["der_paths"]:
                # Try to build from path and test again
                bip32_from_path = Bip32.FromSeedAndPath(binascii.unhexlify(test["seed"]), chain["path"])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        for test in TEST_VECT_BIP32:
            # Create from private extended key
            bip32_ctx = Bip32.FromExtendedKey(test["master"]["ex_priv"])
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Same test for derivation paths
            for chain in test["der_paths"]:
                # Create from private extended key
                bip32_ctx = Bip32.FromExtendedKey(chain["ex_priv"])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

    # Test public derivation
    def test_public_derivation(self):
        # Construct from extended private key
        bip32_ctx = Bip32.FromExtendedKey(TEST_VECT_PUBLIC_DER["ex_priv"])
        # Shall not be public
        self.assertFalse(bip32_ctx.IsPublicOnly())

        # Convert to public
        bip32_ctx.ConvertToPublic()
        # Shall be public and the public key shall be correct
        self.assertTrue(bip32_ctx.IsPublicOnly())
        self.assertEqual(TEST_VECT_PUBLIC_DER["ex_pub"], bip32_ctx.PublicKey().ToExtended())
        # Getting the private key shall raise an exception
        self.assertRaises(Bip32KeyError, bip32_ctx.PrivateKey)
        self.assertRaises(Bip32KeyError, bip32_ctx.EcdsaPrivateKey)

        # Test derivation paths
        for test in TEST_VECT_PUBLIC_DER["der_paths"]:
            # Public derivation does not support hardened indexes
            if Bip32Utils.IsHardenedIndex(test["index"]):
                self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, test["index"])
            else:
                bip32_ctx = bip32_ctx.ChildKey(test["index"])
                self.assertEqual(test["ex_pub"], bip32_ctx.PublicKey().ToExtended())

    # Test invalid seed
    def test_invalid_seed(self):
        for test in TEST_VECT_SEED_ERR:
            self.assertRaises(ValueError, Bip32.FromSeed, binascii.unhexlify(test))

    # Test invalid extended key
    def test_invalid_ex_key(self):
        for test in TEST_VECT_EX_KEY_ERR:
            self.assertRaises(Bip32KeyError, Bip32.FromExtendedKey, test)
