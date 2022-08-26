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
from bip_utils import CoinsConf, P2WPKHAddr, P2WPKHAddrDecoder, P2WPKHAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "address_dec": b"9c90f934ea51fa0f6504177043e0908da6929983",
        "address_params": {
            "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    },
    {
        "pub_key": b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
        "address_dec": b"5e56706b0da301b78a49c2767da6046cb8fea8a8",
        "address_params": {
            "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "bc1qtet8q6cd5vqm0zjfcfm8mfsydju0a29ggqrmu9",
    },
    {
        "pub_key": b"021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17",
        "address_dec": b"77f2208e272bef80e98ce956e05d5ed8f596f5a3",
        "address_params": {
            "hrp": CoinsConf.LitecoinMainNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
    },
    {
        "pub_key": b"0201084ea04fa9619a056281e7c87a97693f67e5baa4ec604e7e8245b84e31cc96",
        "address_dec": b"6c96354b14e73437c20a4e3248b64cb5ffcf4b86",
        "address_params": {
            "hrp": CoinsConf.LitecoinMainNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "ltc1qdjtr2jc5uu6r0ss2fcey3djvkhlu7jux420fhr",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
        "address_dec": b"334924eaf46e806e86b3537a12f81595030d73a7",
        "address_params": {
            "hrp": CoinsConf.BitcoinTestNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
    },
    {
        "pub_key": b"03bb5db212192d5b428c5db726aba21426d0a63b7a453b0104f2398326bca43fc2",
        "address_dec": b"d7bc5f47ee7bbc5d216b0928a4a8ba903bdb404f",
        "address_params": {
            "hrp": CoinsConf.LitecoinTestNet.ParamByKey("p2wpkh_hrp"),
        },
        "address": "tltc1q677973lw0w796gttpy52f296jqaaksz0duklcr",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "ac1qpgmhz30d29akc670hkaje398hl6hvh0csvx4nm",
    # Invalid witness version
    "bc1pyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msq4xugp",
    # No separator
    "bcqnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    # Invalid checksum
    "bc1qpgmhz30d29akc670hkaje398hl6hvh0chf364x",
    # Invalid encoding
    "bc1qnjg0jd8228aq7egyzbcy8cys3knf9xvrerkf9g",
    # Invalid lengths
    "bc1qxac5tm230dkxhnaahvkvffal74m9m7qvzkhtl",
    "bc1qpgmhz30d29akc670hkaje398hl6hvh0c0qqqppggpy",
]


#
# Tests
#
class P2WPKHTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(P2WPKHAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(P2WPKHAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            P2WPKHAddrDecoder,
            {
                "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            P2WPKHAddrEncoder,
            {"hrp": ""},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(P2WPKHAddr is P2WPKHAddrEncoder)
