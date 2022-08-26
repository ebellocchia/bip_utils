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
from bip_utils import FilSecp256k1Addr, FilSecp256k1AddrDecoder, FilSecp256k1AddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0258742e7596b2cb998b42dddffd7b5c7ba30702876f899d6f7188d23285fc3208",
        "address_dec": b"3c07040c8746bfe1485021ca57623f866edd15d4",
        "address_params": {},
        "address": "f1hqdqidehi276cscqehffoyr7qzxn2foumjpq5zq",
    },
    {
        "pub_key": b"03ad9c631c2fac4adca03c1abf9e473dc9bd6dca7868e6b961ebb81547819c6e8c",
        "address_dec": b"b3f7b860d78adcde02e33a19d141782bebfed9ca",
        "address_params": {},
        "address": "f1wp33qygxrlon4axdhim5cqlyfpv75wokvcfdgyy",
    },
    {
        "pub_key": b"036d34f7fde5eedcea7c35e59112abee4786190cec263469b8a92fa15222999cff",
        "address_dec": b"9ddfdb18c55926e6817d4545c1886a30a487d8dc",
        "address_params": {},
        "address": "f1txp5wggfletonal5ivc4dcdkgcsipwg4fte42wi",
    },
    {
        "pub_key": b"03560c22685ce5837b897bd553a4e23af0bf464ef72ddbb32d252d1fbcec4f8c81",
        "address_dec": b"56cc818223ca3165efed0b4b600fc4011cc87f97",
        "address_params": {},
        "address": "f1k3gidardziywl37nbnfwad6eaeomq74xwcs2wxq",
    },
    {
        "pub_key": b"021e8c1330274bd99ba01e019f2cbe07e8822f8b8919f4c1cb38d389903d67f158",
        "address_dec": b"66b8a34e79114e30c6d8f96eb486878afc398c50",
        "address_params": {},
        "address": "f1m24kgttzcfhdbrwy7fxljbuhrl6dtdcqhy4xnla",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "g1k3gidardziywl37nbnfwad6eaeomq74xwcs2wxq",
    # Invalid address type
    "f2m24kgttzcfhdbrwy7fxljbuhrl6dtdcqhy4xnla",
    # Invalid encoding
    "f1hqdqidehi276cscqehffoyr7qzxn2f0umjpq5zq",
    # Invalid checksum
    "f1y7pzdgdbeuuhazhrreys26a22fcv4ycjpi6hrxa",
    # Invalid lengths
    "f1y7pzdgdbeuuhazhrreys26a22fcv4ycjrxwpq",
    "f1y7pzdgdbeuuhazhrreys26a22fcv4ycjlelq3qtb",
]


#
# Tests
#
class FilAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(FilSecp256k1AddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(FilSecp256k1AddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(FilSecp256k1AddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            FilSecp256k1AddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(FilSecp256k1Addr is FilSecp256k1AddrEncoder)
