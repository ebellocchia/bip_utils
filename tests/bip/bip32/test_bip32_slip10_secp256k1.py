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
from bip_utils import Bip32KeyIndex, Bip32Secp256k1, Bip32Slip10Secp256k1, EllipticCurveTypes
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import Bip32BaseTests


# Tests from BIP32 and SLIP-0010 pages
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.SECP256K1,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            "ex_priv": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            "pub_key": "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            "priv_key": "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "chain_code": "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "ex_priv": "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "pub_key": "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                "priv_key": "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "chain_code": "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "parent_fprint": "3442193e",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "ex_priv": "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "pub_key": "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
                "priv_key": "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "chain_code": "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                "parent_fprint": "5c1bd648",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "ex_priv": "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "pub_key": "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
                "priv_key": "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "chain_code": "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                "parent_fprint": "bef5a2f9",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "ex_priv": "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "pub_key": "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
                "priv_key": "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "chain_code": "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                "parent_fprint": "ee7ab90c",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                "ex_priv": "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "pub_key": "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
                "priv_key": "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "chain_code": "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                "parent_fprint": "d880d7d8",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.SECP256K1,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            "ex_priv": "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            "pub_key": "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            "priv_key": "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
            "chain_code": "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "ex_priv": "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "pub_key": "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                "priv_key": "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                "chain_code": "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "parent_fprint": "bd16bee5",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "ex_priv": "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "pub_key": "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
                "priv_key": "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                "chain_code": "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                "parent_fprint": "5a61ff8e",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "ex_priv": "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "pub_key": "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
                "priv_key": "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                "chain_code": "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                "parent_fprint": "d8ab4937",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "ex_priv": "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "pub_key": "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
                "priv_key": "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                "chain_code": "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                "parent_fprint": "78412e3a",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                "ex_priv": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "pub_key": "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
                "priv_key": "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                "chain_code": "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                "parent_fprint": "31a507b8",
            },
        ],
    },
    {
        "seed": b"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
        "curve_type": EllipticCurveTypes.SECP256K1,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            "ex_priv": "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
            "pub_key": "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669",
            "priv_key": "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
            "chain_code": "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                "ex_priv": "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "pub_key": "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2",
                "priv_key": "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
                "chain_code": "e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd",
                "parent_fprint": "41d63b50",
            },
        ],
    },
]

# Tests for public derivation from extended key
TEST_VECT_PUBLIC_DER_EX_KEY = {
    "ex_pub": "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
    "ex_priv": "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
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
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Tests for public derivation from public key
TEST_VECT_PUBLIC_DER_PUB_KEY = {
    "pub_key": "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
    "priv_key": "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "pub_key": "02305e20d8d1e7a398c79ba12965bc11f317a325acb01237f620d16a5b1515ab59",
        },
        # m/0/0
        {
            "index": 0,
            "pub_key": "03b0b376563ed920b460e348df3b88151fed329cfa322137112a658e33aca1e405",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
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
    # Invalid private key (secret is zero)
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisrXZJziEEC1DUnKroSfeGxPp2YKsFRobQpLPsPTCU64kGZdiNbk",
    # Invalid master key (fingerprint is not valid)
    "xprv9s21ZrQZgP7FPptNcV6ZuWeytnfAsNFoPXFUTMDdUQpc44ZhfkDAnctGeUuywWTKXEFwLFGRPGd9WcjbTDdjKU25eRw5REDTVxfiAxZFhrV",
    # Invalid master key (index is not zero)
    "xprv9s21ZrQH143K5p8oLYasVfWDcfK9E5HPajvc6vEmTG592KSs8jk4fb3vA6ZoueJM4oi7xTrbbfU5MyTPRLFPbXLr3TZjQw4rXFQ7v1sk7C4",
    # Public key with invalid lengths (generated on purpose to have a correct checksum)
    "Deb7pNXSbX7qSvc2eGeABhmbP4NtSvzK8Zj7b7r274bnBLKBTFij65e4arfMPqwHT5H4W999v3nbNFxMihTEhMFH856EVAof9BHHRU4B7e9eLy",
    "5FQT7TT6bZmQ6QjZkb19sNtYykPHBpf3tH85ETG1Z92iLoCZsPmxv752kGNCmB4uJcXSayXEPBMabB4mShkm6Uwpg8Lb6Q4ixD8r6bxwdha889BTF",
    # Invalid public key (it's a private key with public net version, generated on purpose)
    "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCj3rW1cw1qdn2KJo1MSajvp3cr5ceA5nJT3QHp65rcYr8AUbzLPh",
]


#
# Tests
#
class Bip32Slip10Secp256k1Tests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(Bip32Slip10Secp256k1.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(Bip32Slip10Secp256k1, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(Bip32Slip10Secp256k1, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(Bip32Slip10Secp256k1, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(Bip32Slip10Secp256k1, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(Bip32Slip10Secp256k1, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(Bip32Slip10Secp256k1, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        self._test_public_derivation_ex_key(Bip32Slip10Secp256k1, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        self._test_public_derivation_pub_key(Bip32Slip10Secp256k1, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(Bip32Slip10Secp256k1, EllipticCurveTypes.SECP256K1)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(Bip32Slip10Secp256k1, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(Bip32Slip10Secp256k1, b"\x00" * (Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN - 1))

    # Test old class
    def test_old_cls(self):
        self.assertTrue(Bip32Secp256k1 is Bip32Slip10Secp256k1)
