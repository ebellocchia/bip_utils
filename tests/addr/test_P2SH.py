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
    BitcoinConf, BitcoinCashConf, BitcoinSvConf, DashConf, DogecoinConf, LitecoinConf, ZcashConf,
    P2SHAddr, BchP2SHAddr
)
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey

# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        "addr_params": {"net_ver": BitcoinConf.P2SH_NET_VER_MN},
        "address": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    },
    {
        "pub_key": b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
        "addr_params": {"net_ver": BitcoinConf.P2SH_NET_VER_MN},
        "address": "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
    },
    {
        "pub_key": b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        "addr_params": {"net_ver": BitcoinSvConf.P2SH_NET_VER_MN},
        "address": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    },
    {
        "pub_key": b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
        "addr_params": {"net_ver": BitcoinSvConf.P2SH_NET_VER_MN},
        "address": "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
    },
    {
        "pub_key": b"024d8d027d63a5787b212f38bc76eca8e5e57415355f51de54e495ca1c66279f68",
        "addr_params": {"net_ver": DashConf.P2SH_NET_VER_MN},
        "address": "7Y5u3566rd7s3dcyDXwDHgvK5VLVhzoeoy",
    },
    {
        "pub_key": b"026243828e14bf0f2d89d180f7a67494198a6cb058b3455c0651cb064c4f20ad48",
        "addr_params": {"net_ver": DashConf.P2SH_NET_VER_MN},
        "address": "7obR8rAq66A24U7wwbBk35AFD5ThFjLcLH",
    },
    {
        "pub_key": b"03f3b10f13fa36775245758f05d1cf650095091c0ef5f2a60c5903c9bee9be91bd",
        "addr_params": {"net_ver": DogecoinConf.P2SH_NET_VER_MN},
        "address": "9xzLEaWbi3eVzRzv6YdGcXbXQMHydntSq7",
    },
    {
        "pub_key": b"03f5a09bdf9a112f60c2da18d2df7470408ed16214fc3f4fb45cbb2a2539abfc1b",
        "addr_params": {"net_ver": DogecoinConf.P2SH_NET_VER_MN},
        "address": "ABxNotFnVaS85dcyXY76d2Fbr12qph6UTy",
    },
    {
        "pub_key": b"0224ca66698d0c4865a8718a3d35c696f140e4d15c24f4d9415e599db3d75daf39",
        "addr_params": {"net_ver": LitecoinConf.P2SH_STD_NET_VER_MN},
        "address": "MJfELhwt9S6Sr9hadHGsnTELZzFUVjMrFc",
    },
    {
        "pub_key": b"039b6933bd6bb28bf30895756d2c7ce11b7c6bc20e6f51ca472463128da1402359",
        "addr_params": {"net_ver": LitecoinConf.P2SH_STD_NET_VER_MN},
        "address": "MQJA6RzwpcX4BWUCqSqxDCLfYHzgYna6cr",
    },
    {
        "pub_key": b"024807e7f516f96703f8c73c908352f502411b7b33a21baa1612029aafc602e7a6",
        "addr_params": {"net_ver": ZcashConf.P2SH_NET_VER_MN},
        "address": "t3PDRLn9XNChQHFJ3826hT7yvv1or9gg52H",
    },
    {
        "pub_key": b"03400161608a4b1b7996c705ad38e1099bdb2753723f90daa37957bfa8c093ca9c",
        "addr_params": {"net_ver": ZcashConf.P2SH_NET_VER_MN},
        "address": "t3aFk4wDnEgJ1HB1yKXhmqsGZDAcrvpEGXv",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
        "addr_params": {"net_ver": BitcoinConf.P2SH_NET_VER_TN},
        "address": "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
    },
    {
        "pub_key": b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
        "addr_params": {"net_ver": BitcoinSvConf.P2SH_NET_VER_TN},
        "address": "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
    },
    {
        "pub_key": b"03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",
        "addr_params": {"net_ver": DashConf.P2SH_NET_VER_TN},
        "address": "8j7NLynPotJD3x4MHGemN36XPSLBKr6cYn",
    },
    {
        "pub_key": b"03765505df9cc00d2cd578c961a494214402283b9f6e8f28684e8798862057a02b",
        "addr_params": {"net_ver": DogecoinConf.P2SH_NET_VER_TN},
        "address": "2MuKeQzUHhUQWUZgx5AuNWoQ7YWx6vsXxrv",
    },
    {
        "pub_key": b"0222319350a9618e5780c3906662e96033284d031be377ae0e9d209de6f4e3e1e3",
        "addr_params": {"net_ver": LitecoinConf.P2SH_STD_NET_VER_TN},
        "address": "QNE4UhQ5mF8HhBEQYijn7V6pT2mgKExQCy",
    },
    {
        "pub_key": b"02ffa169a294a03f1ba97a45760ab4af189633d4936ddaaef6e5dee11a968818e0",
        "addr_params": {"net_ver": ZcashConf.P2SH_NET_VER_TN},
        "address": "t2LfG2nqiWh2u3JkRvYCG4KUKJER5qHhegm",
    },
]


# Tests for Bitcoin Cash
TEST_VECT_BCH = [
    # Main nets
    {
        "pub_key": b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        "addr_params": {"hrp": BitcoinCashConf.P2SH_STD_HRP_MN,
                        "net_ver": BitcoinCashConf.P2SH_STD_NET_VER_MN},
        "address": "bitcoincash:pqlmd62cztjhhdrfr7dy5c5gv2np5nmknvhfvqp85n",
    },
    {
        "pub_key": b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
        "addr_params": {"hrp": BitcoinCashConf.P2SH_STD_HRP_MN,
                        "net_ver": BitcoinCashConf.P2SH_STD_NET_VER_MN},
        "address": "bitcoincash:prlqav3u50a76ln0u8hy7rj5pnjvz68yd5tkse7wf8",
    },
    # Test nets
    {
        "pub_key": b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
        "addr_params": {"hrp": BitcoinCashConf.P2SH_STD_HRP_TN,
                        "net_ver": BitcoinCashConf.P2SH_STD_NET_VER_TN},
        "address": "bchtest:pzqawj7d8qxqtau3686vsxph2ew7exerfg60w5xcq0",
    },
]


#
# Tests
#
class P2SHTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, P2SHAddr, Secp256k1PublicKey, TEST_VECT)
        AddrBaseTestHelper.test_encode_key(self, BchP2SHAddr, Secp256k1PublicKey, TEST_VECT_BCH)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             P2SHAddr,
                                             {"net_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
        AddrBaseTestHelper.test_invalid_keys(self,
                                             BchP2SHAddr,
                                             {"hrp": "", "net_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
