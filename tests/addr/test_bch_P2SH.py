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
from bip_utils import BchP2SHAddr, BchP2SHAddrDecoder, BchP2SHAddrEncoder, CoinsConf
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    # Main nets
    {
        "pub_key": b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        "address_dec": b"3fb6e95812e57bb4691f9a4a628862a61a4f769b",
        "address_params": {"hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_net_ver")},
        "address": "bitcoincash:pqlmd62cztjhhdrfr7dy5c5gv2np5nmknvhfvqp85n",
    },
    {
        "pub_key": b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
        "address_dec": b"fe0eb23ca3fbed7e6fe1ee4f0e540ce4c168e46d",
        "address_params": {"hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_net_ver")},
        "address": "bitcoincash:prlqav3u50a76ln0u8hy7rj5pnjvz68yd5tkse7wf8",
    },
    # Test nets
    {
        "pub_key": b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
        "address_dec": b"81d74bcd380c05f791d1f4c81837565dec9b234a",
        "address_params": {"hrp": CoinsConf.BitcoinCashTestNet.ParamByKey("p2sh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashTestNet.ParamByKey("p2sh_std_net_ver")},
        "address": "bchtest:pzqawj7d8qxqtau3686vsxph2ew7exerfg60w5xcq0",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "bitcaincash:qq9rwu29a4ghkmrte77mktxy57ll2ajalq07scrad4",
    # Invalid net version
    "bitcoincash:qy9rwu29a4ghkmrte77mktxy57ll2ajalqlusxt7x5",
    # No separator
    "bitcoincashqrvcdmgpk73zyfd8pmdl9wnuld36zh9n4gms8s0u59",
    # Invalid checksum
    "bitcoincash:qy9rwu29a4ghkmrte77mktxy57ll2ajalqdhut084g",
    # Invalid encoding
    "bitcoincash:qy9rwu29b4ghkmrte77mktxy57ll2ajalqlusxt7x5",
    # Invalid lengths
    "bitcoincash:qqmhz30d29akc670hkaje398hl6hvh0cxn9sqwnk",
    "bitcoincash:qq9rwu29a4ghkmrte77mktxy57ll2ajalqqqawuuxup8",
]


#
# Tests
#
class BchP2SHTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(BchP2SHAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(BchP2SHAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            BchP2SHAddrDecoder,
            {
                "hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_hrp"),
                "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2sh_std_net_ver"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            BchP2SHAddrEncoder,
            {"hrp": "", "net_ver": b"\x00"},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(BchP2SHAddr is BchP2SHAddrEncoder)
