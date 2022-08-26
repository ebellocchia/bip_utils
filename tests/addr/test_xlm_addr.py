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
from bip_utils import XlmAddr, XlmAddrDecoder, XlmAddrEncoder, XlmAddrTypes
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"004342d377174aeabce717c67d66df8ba7a8f3835d3c6e978b8bdb63a444d2f6ab",
        "address_dec": b"4342d377174aeabce717c67d66df8ba7a8f3835d3c6e978b8bdb63a444d2f6ab",
        "address_params": {},
        "address": "GBBUFU3XC5FOVPHHC7DH2ZW7ROT2R44DLU6G5F4LRPNWHJCE2L3KWRPA",
    },
    {
        "pub_key": b"0073658385894c3c9f01a15e9f97d7d65f24d8f7bb1656bfe79a6f7512de132b68",
        "address_dec": b"73658385894c3c9f01a15e9f97d7d65f24d8f7bb1656bfe79a6f7512de132b68",
        "address_params": {
            "addr_type": XlmAddrTypes.PUB_KEY,
        },
        "address": "GBZWLA4FRFGDZHYBUFPJ7F6X2ZPSJWHXXMLFNP7HTJXXKEW6CMVWQTNY",
    },
    {
        "pub_key": b"00eaf531f163a1e91da0a5dbb198fab8ec06b42296ceff584781c42f04eb1ba87c",
        "address_dec": b"eaf531f163a1e91da0a5dbb198fab8ec06b42296ceff584781c42f04eb1ba87c",
        "address_params": {
            "addr_type": XlmAddrTypes.PUB_KEY,
        },
        "address": "GDVPKMPRMOQ6SHNAUXN3DGH2XDWANNBCS3HP6WCHQHCC6BHLDOUHZ25S",
    },
    {
        "pub_key": b"eea5fe0eb96b032d0067fc35fd2c2579e408d437e8d6f9be9d3f9246f24f9b95",
        "address_dec": b"eea5fe0eb96b032d0067fc35fd2c2579e408d437e8d6f9be9d3f9246f24f9b95",
        "address_params": {
            "addr_type": XlmAddrTypes.PUB_KEY,
        },
        "address": "GDXKL7QOXFVQGLIAM76DL7JMEV46ICGUG7UNN6N6TU7ZERXSJ6NZLIGP",
    },
    {
        "pub_key": b"046e316bc3207638f91823bb4822c6562e8aef15f3ce7e35df75f7bf6081fd81",
        "address_dec": b"046e316bc3207638f91823bb4822c6562e8aef15f3ce7e35df75f7bf6081fd81",
        "address_params": {
            "addr_type": XlmAddrTypes.PUB_KEY,
        },
        "address": "GACG4MLLYMQHMOHZDAR3WSBCYZLC5CXPCXZ447RV3527PP3AQH6YCMW5",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid address type
    "SAVQKOGHY44KG4BYLXEUAT5542L6FHISIPL5P5OF4VML6S7HHC4CZMYQ",
    # Invalid checksum
    "GAVQKOGHY44KG4BYLXEUAT5542L6FHISIPL5P5OF4VML6S7HHC4CY3ZB",
    # Invalid encoding
    "GBBUFU3XC5F0VPHHC7DH2ZW7ROT2R44DLU6G5F4LRPNWHJCE2L3KWRPA",
    # Invalid public key
    "GDJEZMT3ZZ3IX2HAG7CI2HYD2S6WIH5G2IJHHD3B2GLHP6QIHBJAESYD",
    # Invalid lengths
    "GACTRR6HHCRXAOC5ZFAE7PPGS7RJ2ESD27L7LRPFLC7UXZZYXAWAITY",
    "GAACWBJYY7DTRI3QHBO4SQCPXXTJPYU5CJB5PV7VYXSVRP2L444LQLHSP4",
]


#
# Tests
#
class XlmAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(XlmAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(XlmAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            XlmAddrDecoder,
            {
                "addr_type": XlmAddrTypes.PUB_KEY,
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            XlmAddrEncoder,
            {
                "addr_type": XlmAddrTypes.PUB_KEY,
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            XlmAddrDecoder,
            {"addr_type": 0},
            TypeError
        )
        self._test_invalid_params_enc(
            XlmAddrEncoder,
            {"addr_type": 0},
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(XlmAddr is XlmAddrEncoder)
