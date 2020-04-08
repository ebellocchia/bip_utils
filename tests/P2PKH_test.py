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
from bip_utils import BitcoinConf, LitecoinConf, DogecoinConf, DashConf, P2PKH


# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        #
        # Main nets
        #
        {
            "pub_key"      : b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
            "address"      :  "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            "net_addr_ver" :  BitcoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
            "address"      :  "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
            "net_addr_ver" :  BitcoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"02a233494d46445b70a7bc3c5b376f1233e6a3acdc866b1566473984518e275dbc",
            "address"      :  "LX4YojYdeBk3TtUcryCcgAqYxjicKfK7AD",
            "net_addr_ver" :  LitecoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"02632b96b6e6b9fc242a5fa23a0015d447746c8a3d82fc412e2924a6c184457e3b",
            "address"      :  "LVYs6bw81eLpkqGtsHWDNFbssZPPdNcL4G",
            "net_addr_ver" :  LitecoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"025a8ad8881f6facdc949c4a4d03257414153faea67e96acf57344660080610788",
            "address"      :  "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas",
            "net_addr_ver" :  DogecoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"03b4b21789f999f8c268d77ff0f6ed80884ec088ddd1b2d10055981d6bc393308a",
            "address"      :  "DTdrvUHbk5oMyi62tM7LqrjAcXfqB7eaad",
            "net_addr_ver" :  DogecoinConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"03146d29e4a8b263f607f6ffae0a19f2e9be0bc063783e3658f50255c380b45070",
            "address"      :  "XnLyZhQDr3JqFQi7UPC8LddHMgbAyQWiZo",
            "net_addr_ver" :  DashConf.P2PKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"02b80e30b1cfbd4e172212110f914b66cdaa83967eade9c9884571906164a8cc44",
            "address"      :  "XykvvzP3nK2KRLKkpCe6hHV6p2w5DNQD56",
            "net_addr_ver" :  DashConf.P2PKH_NET_VER["main"],
        },
        #
        # Test nets
        #
        {
            "pub_key"      : b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
            "address"      :  "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
            "net_addr_ver" :  BitcoinConf.P2PKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"03be3878cb32ea37037b6d906ca8dfadc8bf511305194e24093379e19ea8fce04e",
            "address"      :  "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp",
            "net_addr_ver" :  LitecoinConf.P2PKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"02b9988be7219be78b82e659155d02d3e1462f3febe7c87d33964b37831efd8884",
            "address"      :  "nprZmJBRhatuwtUXBSjjd3nCG9R8DDm3y3",
            "net_addr_ver" :  DogecoinConf.P2PKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"03ee6c2e9fcb33d45966775d41990c68d6b4db14bb66044fbb591b3f313781d612",
            "address"      :  "ygAN9888Yy9thRdvaFuGqHa3Qm4M3Cvrj9",
            "net_addr_ver" :  DashConf.P2PKH_NET_VER["test"],
        },
    ]

# Some invalid keys
TEST_VECTOR_KEY_ERR = \
    [
        # Private key (not accepted by P2PKH)
        b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
        # Compressed public key with valid length but wrong version (0x01)
        b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
        # Compressed public key with invalid length
        b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
        # Uncompressed public key (not accepted by P2PKH)
        b"aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e9370164133294e5fd1679672fe7866c307daf97281a28f66dca7cbb52919824f"
    ]


#
# Tests
#
class P2PKHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            self.assertEqual(test["address"], P2PKH.ToAddress(binascii.unhexlify(test["pub_key"]), test["net_addr_ver"]))

    # Test invalid keys
    def test_invalid_keys(self):
        for test in TEST_VECTOR_KEY_ERR:
            self.assertRaises(ValueError, P2PKH.ToAddress, binascii.unhexlify(test))


# Run test if executed
if __name__ == "__main__":
    unittest.main()
