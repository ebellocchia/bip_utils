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
from bip_utils import CoinsConf, BchP2PKHAddr
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey

# Some random public keys
TEST_VECT = [
    # Main nets
    {
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "addr_params": {"hrp": CoinsConf.BitcoinCashMainNet.Params("p2sh_std_hrp"),
                        "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver")},
        "address": "bitcoincash:qrvcdmgpk73zyfd8pmdl9wnuld36zh9n4gms8s0u59",
    },
    {
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "addr_params": {"hrp": CoinsConf.BitcoinCashMainNet.Params("p2sh_std_hrp"),
                        "net_ver": CoinsConf.BitcoinCashMainNet.Params("p2pkh_std_net_ver")},
        "address": "bitcoincash:qpceft8d22pq4894wm9nh673y9rz7wwtpu6ryz8hlr",
    },
    # Test nets
    {
        "pub_key": b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "addr_params": {"hrp": CoinsConf.BitcoinCashTestNet.Params("p2sh_std_hrp"),
                        "net_ver": CoinsConf.BitcoinCashTestNet.Params("p2pkh_std_net_ver")},
        "address": "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4",
    },
]


#
# Tests
#
class BchP2PKHTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, BchP2PKHAddr, Secp256k1PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             BchP2PKHAddr,
                                             {"hrp": "", "net_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
