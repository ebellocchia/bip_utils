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
from bip_utils import (
    BitcoinConf, BitcoinCashConf, BitcoinSvConf, LitecoinConf, DogecoinConf, DashConf, ZcashConf,
    P2SH, BchP2SH
    )


# Some random public keys (verified with https://iancoleman.io/bip39/ when possible)
TEST_VECT = \
    [
        #
        # Main nets
        #
        {
            "pub_key"      : b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
            "address"      :  "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
            "address"      :  "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
            "address"      :  "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            "net_addr_ver" :  BitcoinSvConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
            "address"      :  "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
            "net_addr_ver" :  BitcoinSvConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"0224ca66698d0c4865a8718a3d35c696f140e4d15c24f4d9415e599db3d75daf39",
            "address"      :  "MJfELhwt9S6Sr9hadHGsnTELZzFUVjMrFc",
            "net_addr_ver" :  LitecoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"039b6933bd6bb28bf30895756d2c7ce11b7c6bc20e6f51ca472463128da1402359",
            "address"      :  "MQJA6RzwpcX4BWUCqSqxDCLfYHzgYna6cr",
            "net_addr_ver" :  LitecoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"03f3b10f13fa36775245758f05d1cf650095091c0ef5f2a60c5903c9bee9be91bd",
            "address"      :  "9xzLEaWbi3eVzRzv6YdGcXbXQMHydntSq7",
            "net_addr_ver" :  DogecoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"03f5a09bdf9a112f60c2da18d2df7470408ed16214fc3f4fb45cbb2a2539abfc1b",
            "address"      :  "ABxNotFnVaS85dcyXY76d2Fbr12qph6UTy",
            "net_addr_ver" :  DogecoinConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"024d8d027d63a5787b212f38bc76eca8e5e57415355f51de54e495ca1c66279f68",
            "address"      :  "7Y5u3566rd7s3dcyDXwDHgvK5VLVhzoeoy",
            "net_addr_ver" :  DashConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"026243828e14bf0f2d89d180f7a67494198a6cb058b3455c0651cb064c4f20ad48",
            "address"      :  "7obR8rAq66A24U7wwbBk35AFD5ThFjLcLH",
            "net_addr_ver" :  DashConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"024807e7f516f96703f8c73c908352f502411b7b33a21baa1612029aafc602e7a6",
            "address"      :  "t3PDRLn9XNChQHFJ3826hT7yvv1or9gg52H",
            "net_addr_ver" :  ZcashConf.P2SH_NET_VER.Main(),
        },
        {
            "pub_key"      : b"03400161608a4b1b7996c705ad38e1099bdb2753723f90daa37957bfa8c093ca9c",
            "address"      :  "t3aFk4wDnEgJ1HB1yKXhmqsGZDAcrvpEGXv",
            "net_addr_ver" :  ZcashConf.P2SH_NET_VER.Main(),
        },
        #
        # Test nets
        #
        {
            "pub_key"      : b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
            "address"      :  "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER.Test(),
        },
        {
            "pub_key"      : b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
            "address"      :  "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
            "net_addr_ver" :  BitcoinSvConf.P2SH_NET_VER.Test(),
        },
        {
            "pub_key"      : b"0222319350a9618e5780c3906662e96033284d031be377ae0e9d209de6f4e3e1e3",
            "address"      :  "QNE4UhQ5mF8HhBEQYijn7V6pT2mgKExQCy",
            "net_addr_ver" :  LitecoinConf.P2SH_NET_VER.Test(),
        },
        {
            "pub_key"      : b"03765505df9cc00d2cd578c961a494214402283b9f6e8f28684e8798862057a02b",
            "address"      :  "2MuKeQzUHhUQWUZgx5AuNWoQ7YWx6vsXxrv",
            "net_addr_ver" :  DogecoinConf.P2SH_NET_VER.Test(),
        },
        {
            "pub_key"      : b"03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",
            "address"      :  "8j7NLynPotJD3x4MHGemN36XPSLBKr6cYn",
            "net_addr_ver" :  DashConf.P2SH_NET_VER.Test(),
        },

        {
            "pub_key"      : b"02ffa169a294a03f1ba97a45760ab4af189633d4936ddaaef6e5dee11a968818e0",
            "address"      :  "t2LfG2nqiWh2u3JkRvYCG4KUKJER5qHhegm",
            "net_addr_ver" :  ZcashConf.P2SH_NET_VER.Test(),
        },
    ]

# Tests for Bitcoin Cash
TEST_VECT_BCH = \
    [
        # Main nets
        {
            "pub_key"      : b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
            "address"      :  "bitcoincash:pqlmd62cztjhhdrfr7dy5c5gv2np5nmknvhfvqp85n",
            "hrp"          :  BitcoinCashConf.BCH_P2SH_NET_VER.Main()["hrp"],
            "net_addr_ver" :  BitcoinCashConf.BCH_P2SH_NET_VER.Main()["net_ver"],
        },
        {
            "pub_key"      : b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
            "address"      :  "bitcoincash:prlqav3u50a76ln0u8hy7rj5pnjvz68yd5tkse7wf8",
            "hrp"          :  BitcoinCashConf.BCH_P2SH_NET_VER.Main()["hrp"],
            "net_addr_ver" :  BitcoinCashConf.BCH_P2SH_NET_VER.Main()["net_ver"],
        },
        # Test nets
        {
            "pub_key"      : b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
            "address"      :  "bchtest:pzqawj7d8qxqtau3686vsxph2ew7exerfg60w5xcq0",
            "hrp"          :  BitcoinCashConf.BCH_P2SH_NET_VER.Test()["hrp"],
            "net_addr_ver" :  BitcoinCashConf.BCH_P2SH_NET_VER.Test()["net_ver"],
        },
    ]

# Tests for invalid keys
TEST_VECT_KEY_INVALID = \
    [
        # Private key (not accepted by P2SH)
        b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
        # Compressed public key with valid length but wrong version (0x01)
        b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
        # Compressed public key with invalid length
        b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
        # Uncompressed public key (not accepted by P2SH)
        b"aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e9370164133294e5fd1679672fe7866c307daf97281a28f66dca7cbb52919824f"
    ]


#
# Tests
#
class P2SHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            self.assertEqual(test["address"], P2SH.ToAddress(binascii.unhexlify(test["pub_key"]), test["net_addr_ver"]))
        for test in TEST_VECT_BCH:
            self.assertEqual(test["address"], BchP2SH.ToAddress(binascii.unhexlify(test["pub_key"]), test["hrp"], test["net_addr_ver"]))

    # Test invalid keys
    def test_invalid_keys(self):
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, P2SH.ToAddress, binascii.unhexlify(test))
            self.assertRaises(ValueError, BchP2SH.ToAddress, binascii.unhexlify(test), "", b"\x00")
