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
from bip_utils import BchP2PKHAddr, BchP2PKHAddrDecoder, BchP2PKHAddrEncoder, CoinsConf
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    # Main nets
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_dec": b"d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa",
        "address_params": {"hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver")},
        "address": "bitcoincash:qrvcdmgpk73zyfd8pmdl9wnuld36zh9n4gms8s0u59",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_dec": b"7194aced52820a9cb576cb3bebd121462f39cb0f",
        "address_params": {"hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver")},
        "address": "bitcoincash:qpceft8d22pq4894wm9nh673y9rz7wwtpu6ryz8hlr",
    },
    # Test nets
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "address_dec": b"3a2d4145a4f098523b3e8127f1da87cfc55b8e79",
        "address_params": {"hrp": CoinsConf.BitcoinCashTestNet.ParamByKey("p2pkh_std_hrp"),
                           "net_ver": CoinsConf.BitcoinCashTestNet.ParamByKey("p2pkh_std_net_ver")},
        "address": "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4",
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
class BchP2PKHTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(BchP2PKHAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(BchP2PKHAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            BchP2PKHAddrDecoder,
            {
                "hrp": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_hrp"),
                "net_ver": CoinsConf.BitcoinCashMainNet.ParamByKey("p2pkh_std_net_ver"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            BchP2PKHAddrEncoder,
            {"hrp": "", "net_ver": b"\x00"},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(BchP2PKHAddr is BchP2PKHAddrEncoder)
