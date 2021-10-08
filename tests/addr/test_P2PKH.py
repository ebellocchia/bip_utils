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
from bip_utils import (
    Bip44BitcoinMainNet, Bip44BitcoinTestNet, Bip44BitcoinSvMainNet, Bip44BitcoinSvTestNet, Bip44BitcoinCashMainNet, Bip44BitcoinCashTestNet,
    Bip44DashMainNet, Bip44DashTestNet, Bip44DogecoinMainNet, Bip44DogecoinTestNet, Bip44LitecoinMainNet, Bip44LitecoinTestNet,
    Bip44ZcashMainNet, Bip44ZcashTestNet,
    P2PKHAddr, BchP2PKHAddr
)
from .test_addr_base import AddrBaseTestHelper
from .test_addr_const import *

# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "addr_params": {"net_ver": Bip44BitcoinMainNet.AddrParamsKey("net_ver")},
        "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "addr_params": {"net_ver": Bip44BitcoinMainNet.AddrParamsKey("net_ver")},
        "address": "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
    },
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "addr_params": {"net_ver": Bip44BitcoinSvMainNet.AddrParamsKey("net_ver")},
        "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "addr_params": {"net_ver": Bip44BitcoinSvMainNet.AddrParamsKey("net_ver")},
        "address": "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
    },
    {
        "pub_key": b"03146d29e4a8b263f607f6ffae0a19f2e9be0bc063783e3658f50255c380b45070",
        "addr_params": {"net_ver": Bip44DashMainNet.AddrParamsKey("net_ver")},
        "address": "XnLyZhQDr3JqFQi7UPC8LddHMgbAyQWiZo",
    },
    {
        "pub_key": b"02b80e30b1cfbd4e172212110f914b66cdaa83967eade9c9884571906164a8cc44",
        "addr_params": {"net_ver": Bip44DashMainNet.AddrParamsKey("net_ver")},
        "address": "XykvvzP3nK2KRLKkpCe6hHV6p2w5DNQD56",
    },
    {
        "pub_key": b"025a8ad8881f6facdc949c4a4d03257414153faea67e96acf57344660080610788",
        "addr_params": {"net_ver": Bip44DogecoinMainNet.AddrParamsKey("net_ver")},
        "address": "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas",
    },
    {
        "pub_key": b"03b4b21789f999f8c268d77ff0f6ed80884ec088ddd1b2d10055981d6bc393308a",
        "addr_params": {"net_ver": Bip44DogecoinMainNet.AddrParamsKey("net_ver")},
        "address": "DTdrvUHbk5oMyi62tM7LqrjAcXfqB7eaad",
    },
    {
        "pub_key": b"02a233494d46445b70a7bc3c5b376f1233e6a3acdc866b1566473984518e275dbc",
        "addr_params": {"net_ver": Bip44LitecoinMainNet.AddrParamsKey("net_ver")},
        "address": "LX4YojYdeBk3TtUcryCcgAqYxjicKfK7AD",
    },
    {
        "pub_key": b"02632b96b6e6b9fc242a5fa23a0015d447746c8a3d82fc412e2924a6c184457e3b",
        "addr_params": {"net_ver": Bip44LitecoinMainNet.AddrParamsKey("net_ver")},
        "address": "LVYs6bw81eLpkqGtsHWDNFbssZPPdNcL4G",
    },
    {
        "pub_key": b"039aeb5d8603d924b0ad36a1081a9a0c0188a9cd8e8782eb79a3a32ae564ca1c2f",
        "addr_params": {"net_ver": Bip44ZcashMainNet.AddrParamsKey("net_ver")},
        "address": "t1Msw6c7mLQbPnHRyTC6NB3y2U2HjcrHiRM",
    },
    {
        "pub_key": b"036a72387457929aa58b1d5654101b0429c141d3971b5378e848db29f574d6751c",
        "addr_params": {"net_ver": Bip44ZcashMainNet.AddrParamsKey("net_ver")},
        "address": "t1T6t4H4zerrZRtkPVuu7fgVBCjRjNMY295",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "addr_params": {"net_ver": Bip44BitcoinTestNet.AddrParamsKey("net_ver")},
        "address": "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
    },
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "addr_params": {"net_ver": Bip44BitcoinSvTestNet.AddrParamsKey("net_ver")},
        "address": "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
    },
    {
        "pub_key": b"03ee6c2e9fcb33d45966775d41990c68d6b4db14bb66044fbb591b3f313781d612",
        "addr_params": {"net_ver": Bip44DashTestNet.AddrParamsKey("net_ver")},
        "address": "ygAN9888Yy9thRdvaFuGqHa3Qm4M3Cvrj9",
    },
    {
        "pub_key": b"02b9988be7219be78b82e659155d02d3e1462f3febe7c87d33964b37831efd8884",
        "addr_params": {"net_ver": Bip44DogecoinTestNet.AddrParamsKey("net_ver")},
        "address": "nprZmJBRhatuwtUXBSjjd3nCG9R8DDm3y3",
    },
    {
        "pub_key": b"03be3878cb32ea37037b6d906ca8dfadc8bf511305194e24093379e19ea8fce04e",
        "addr_params": {"net_ver": Bip44LitecoinTestNet.AddrParamsKey("net_ver")},
        "address": "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp",
    },
    {
        "pub_key": b"0370b963230c857dfdbf9b99835dd1b06d96c2d37c888ca365a56806abd8732f6a",
        "addr_params": {"net_ver": Bip44ZcashTestNet.AddrParamsKey("net_ver")},
        "address": "tmSEwQYGh3dzFu2boSfVeemmqHTjv4LMQFd",
    },
]


# Tests for Bitcoin Cash
TEST_VECT_BCH = [
    # Main nets
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "addr_params": {"hrp": Bip44BitcoinCashMainNet.AddrParamsKey("hrp"),
                        "net_ver": Bip44BitcoinCashMainNet.AddrParamsKey("net_ver")},
        "address": "bitcoincash:qrvcdmgpk73zyfd8pmdl9wnuld36zh9n4gms8s0u59",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "addr_params": {"hrp": Bip44BitcoinCashMainNet.AddrParamsKey("hrp"),
                        "net_ver": Bip44BitcoinCashMainNet.AddrParamsKey("net_ver")},
        "address": "bitcoincash:qpceft8d22pq4894wm9nh673y9rz7wwtpu6ryz8hlr",
    },
    # Test nets
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "addr_params": {"hrp": Bip44BitcoinCashTestNet.AddrParamsKey("hrp"),
                        "net_ver": Bip44BitcoinCashTestNet.AddrParamsKey("net_ver")},
        "address": "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4",
    },
]


#
# Tests
#
class P2PKHTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, P2PKHAddr, Secp256k1PublicKey, TEST_VECT)
        AddrBaseTestHelper.test_encode_key(self, BchP2PKHAddr, Secp256k1PublicKey, TEST_VECT_BCH)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             P2PKHAddr,
                                             {"net_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
        AddrBaseTestHelper.test_invalid_keys(self,
                                             BchP2PKHAddr,
                                             {"hrp": "", "net_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
