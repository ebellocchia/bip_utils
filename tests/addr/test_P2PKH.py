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
from bip_utils import CoinsConf, P2PKHAddr, P2PKHAddrDecoder, P2PKHAddrEncoder, P2PKHPubKeyModes
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_dec": b"d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa",
        "address_params": {
            "net_ver": CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
        },
        "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_dec": b"7194aced52820a9cb576cb3bebd121462f39cb0f",
        "address_params": {
            "net_ver": CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
    },
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_dec": b"5082d39777f1ddfb3a529cf9358aa4f486bdf1aa",
        "address_params": {
            "net_ver": CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.UNCOMPRESSED,
        },
        "address": "18LhnLKXjcTw5xJFiTxntnKit2Gd63eWFm",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_dec": b"ec46fcf981d7766b0eb513b050a471b22fefab5f",
        "address_params": {
            "net_ver": CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.UNCOMPRESSED,
        },
        "address": "1NYKWcokisTwneDVzEV87EX8diaEAii2s3",
    },
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_dec": b"d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa",
        "address_params": {
            "net_ver": CoinsConf.BitcoinSvMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_dec": b"7194aced52820a9cb576cb3bebd121462f39cb0f",
        "address_params": {
            "net_ver": CoinsConf.BitcoinSvMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
    },
    {
        "pub_key": b"03146d29e4a8b263f607f6ffae0a19f2e9be0bc063783e3658f50255c380b45070",
        "address_dec": b"7fdfa4f3bd16f419e2a25e16ad50f03ab69fb414",
        "address_params": {
            "net_ver": CoinsConf.DashMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "XnLyZhQDr3JqFQi7UPC8LddHMgbAyQWiZo",
    },
    {
        "pub_key": b"02b80e30b1cfbd4e172212110f914b66cdaa83967eade9c9884571906164a8cc44",
        "address_dec": b"fd10d02fb864a11513a3d35bbb97c2a4c01ad8a0",
        "address_params": {
            "net_ver": CoinsConf.DashMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "XykvvzP3nK2KRLKkpCe6hHV6p2w5DNQD56",
    },
    {
        "pub_key": b"025a8ad8881f6facdc949c4a4d03257414153faea67e96acf57344660080610788",
        "address_dec": b"3bf96544e911ca728f5fabf5a4f3b65deab684c4",
        "address_params": {
            "net_ver": CoinsConf.DogecoinMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas",
    },
    {
        "pub_key": b"03b4b21789f999f8c268d77ff0f6ed80884ec088ddd1b2d10055981d6bc393308a",
        "address_dec": b"f6c3769584c11aa2fe94721d5d13166d05b73e0a",
        "address_params": {
            "net_ver": CoinsConf.DogecoinMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "DTdrvUHbk5oMyi62tM7LqrjAcXfqB7eaad",
    },
    {
        "pub_key": b"02a233494d46445b70a7bc3c5b376f1233e6a3acdc866b1566473984518e275dbc",
        "address_dec": b"81da2f6aec543ef59cf37623954da842a6a777a6",
        "address_params": {
            "net_ver": CoinsConf.LitecoinMainNet.ParamByKey("p2pkh_std_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "LX4YojYdeBk3TtUcryCcgAqYxjicKfK7AD",
    },
    {
        "pub_key": b"02632b96b6e6b9fc242a5fa23a0015d447746c8a3d82fc412e2924a6c184457e3b",
        "address_dec": b"7144d958e42e367bc86affce6f9dc32fd824ce3b",
        "address_params": {
            "net_ver": CoinsConf.LitecoinMainNet.ParamByKey("p2pkh_std_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "LVYs6bw81eLpkqGtsHWDNFbssZPPdNcL4G",
    },
    {
        "pub_key": b"039aeb5d8603d924b0ad36a1081a9a0c0188a9cd8e8782eb79a3a32ae564ca1c2f",
        "address_dec": b"2bf0707c2475214825a50a0e33adf904ddc9fcf8",
        "address_params": {
            "net_ver": CoinsConf.ZcashMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "t1Msw6c7mLQbPnHRyTC6NB3y2U2HjcrHiRM",
    },
    {
        "pub_key": b"036a72387457929aa58b1d5654101b0429c141d3971b5378e848db29f574d6751c",
        "address_dec": b"653bf022cf92ac75c030bb324f30ee152bff546a",
        "address_params": {
            "net_ver": CoinsConf.ZcashMainNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "t1T6t4H4zerrZRtkPVuu7fgVBCjRjNMY295",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "address_dec": b"3a2d4145a4f098523b3e8127f1da87cfc55b8e79",
        "address_params": {
            "net_ver": CoinsConf.BitcoinTestNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
    },
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "address_dec": b"3a2d4145a4f098523b3e8127f1da87cfc55b8e79",
        "address_params": {
            "net_ver": CoinsConf.BitcoinSvTestNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
    },
    {
        "pub_key": b"03ee6c2e9fcb33d45966775d41990c68d6b4db14bb66044fbb591b3f313781d612",
        "address_dec": b"d9aad77d6108e924e280640dafcbf57bc34ecfb3",
        "address_params": {
            "net_ver": CoinsConf.DashTestNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "ygAN9888Yy9thRdvaFuGqHa3Qm4M3Cvrj9",
    },
    {
        "pub_key": b"02b9988be7219be78b82e659155d02d3e1462f3febe7c87d33964b37831efd8884",
        "address_dec": b"e2a5f07cff5a47a306bf6e5da322063029727fd0",
        "address_params": {
            "net_ver": CoinsConf.DogecoinTestNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "nprZmJBRhatuwtUXBSjjd3nCG9R8DDm3y3",
    },
    {
        "pub_key": b"03be3878cb32ea37037b6d906ca8dfadc8bf511305194e24093379e19ea8fce04e",
        "address_dec": b"4c2e2bf28069045a8eb627c839ff2306b73bba30",
        "address_params": {
            "net_ver": CoinsConf.LitecoinTestNet.ParamByKey("p2pkh_std_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp",
    },
    {
        "pub_key": b"0370b963230c857dfdbf9b99835dd1b06d96c2d37c888ca365a56806abd8732f6a",
        "address_dec": b"b54aefa00bc712c231328e16a8297844f214fad4",
        "address_params": {
            "net_ver": CoinsConf.ZcashTestNet.ParamByKey("p2pkh_net_ver"),
            "pub_key_mode": P2PKHPubKeyModes.COMPRESSED,
        },
        "address": "tmSEwQYGh3dzFu2boSfVeemmqHTjv4LMQFd",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid net version
    "RGdAEmqegTwkWXoR261JfufyFBsy9sDex",
    # Invalid checksum
    "1w2B8UYwW14w5PiPbkgpYdtLjvwGTrend",
    # Invalid length
    "129RDDNmje5fdVHj2db7aAXyq8ayn2JeV",
    "1K9QAFwFNcGKcGqDpSXjna5Si42rGj4DZ44E",
]


#
# Tests
#
class P2PKHTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(P2PKHAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(P2PKHAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            P2PKHAddrDecoder,
            {
                "net_ver": CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            P2PKHAddrEncoder,
            {"net_ver": b"\x00"},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(P2PKHAddr is P2PKHAddrEncoder)
