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
from bip_utils import CoinsConf, P2WPKHAddr
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey

# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "addr_params": {"hrp": CoinsConf.BitcoinMainNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.BitcoinMainNet.Params("p2wpkh_wit_ver")},
        "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    },
    {
        "pub_key": b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
        "addr_params": {"hrp": CoinsConf.BitcoinMainNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.BitcoinMainNet.Params("p2wpkh_wit_ver")},
        "address": "bc1qtet8q6cd5vqm0zjfcfm8mfsydju0a29ggqrmu9",
    },
    {
        "pub_key": b"021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17",
        "addr_params": {"hrp": CoinsConf.LitecoinMainNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.LitecoinMainNet.Params("p2wpkh_wit_ver")},
        "address": "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
    },
    {
        "pub_key": b"0201084ea04fa9619a056281e7c87a97693f67e5baa4ec604e7e8245b84e31cc96",
        "addr_params": {"hrp": CoinsConf.LitecoinMainNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.LitecoinMainNet.Params("p2wpkh_wit_ver")},
        "address": "ltc1qdjtr2jc5uu6r0ss2fcey3djvkhlu7jux420fhr",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
        "addr_params": {"hrp": CoinsConf.BitcoinTestNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.BitcoinTestNet.Params("p2wpkh_wit_ver")},
        "address": "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
    },
    {
        "pub_key": b"03bb5db212192d5b428c5db726aba21426d0a63b7a453b0104f2398326bca43fc2",
        "addr_params": {"hrp": CoinsConf.LitecoinTestNet.Params("p2wpkh_hrp"),
                        "wit_ver": CoinsConf.LitecoinTestNet.Params("p2wpkh_wit_ver")},
        "address": "tltc1q677973lw0w796gttpy52f296jqaaksz0duklcr",
    },
]


#
# Tests
#
class P2WPKHTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, P2WPKHAddr, Secp256k1PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             P2WPKHAddr,
                                             {"hrp": "", "wit_ver": b"\x00"},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
