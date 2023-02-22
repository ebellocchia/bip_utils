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
from bip_utils import AlgoAddr, AlgoAddrDecoder, AlgoAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00999418b6fb585a05e91dc8312b15364eb1a5c5b92fef7472b9e877c44cd6486c",
        "address_dec": b"999418b6fb585a05e91dc8312b15364eb1a5c5b92fef7472b9e877c44cd6486c",
        "address_params": {},
        "address": "TGKBRNX3LBNAL2I5ZAYSWFJWJ2Y2LRNZF7XXI4VZ5B34ITGWJBWBQ7O4GE",
    },
    {
        "pub_key": b"009b8c7c402880a43afa68da22a6ad1aa792194e17794a509ff73f2ffe4ea42501",
        "address_dec": b"9b8c7c402880a43afa68da22a6ad1aa792194e17794a509ff73f2ffe4ea42501",
        "address_params": {},
        "address": "TOGHYQBIQCSDV6TI3IRKNLI2U6JBSTQXPFFFBH7XH4X74TVEEUAVQ22HNU",
    },
    {
        "pub_key": b"007de3673552c74087237a6ffa56c7ae33c85afde8bac8faf2cc9f4c494a894613",
        "address_dec": b"7de3673552c74087237a6ffa56c7ae33c85afde8bac8faf2cc9f4c494a894613",
        "address_params": {},
        "address": "PXRWONKSY5AIOI32N75FNR5OGPEFV7PIXLEPV4WMT5GESSUJIYJ2ZBJRXY",
    },
    {
        "pub_key": b"fc48f2c911ddfd84c794d158f8e406195f5f16723c4747731a8aae01c1f78150",
        "address_dec": b"fc48f2c911ddfd84c794d158f8e406195f5f16723c4747731a8aae01c1f78150",
        "address_params": {},
        "address": "7REPFSIR3X6YJR4U2FMPRZAGDFPV6FTSHRDUO4Y2RKXADQPXQFIJBXUDTI",
    },
    {
        "pub_key": b"fc426991054edcb0ab81bb079df952ba4bdaa0dcfcbb3c32748cf86082950285",
        "address_dec": b"fc426991054edcb0ab81bb079df952ba4bdaa0dcfcbb3c32748cf86082950285",
        "address_params": {},
        "address": "7RBGTEIFJ3OLBK4BXMDZ36KSXJF5VIG47S5TYMTURT4GBAUVAKCURE6GDQ",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid encoding
    "TGKBRNX3LBNAL2I5ZAYSWFJWJ2Y2LRNZF7XXI4VZ5B34ITGWJBWBEJKP0M",
    # Invalid checksum
    "TGKBRNX3LBNAL2I5ZAYSWFJWJ2Y2LRNZF7XXI4VZ5B34ITGWJBWBEJKP5M",
    # Invalid public key
    "2JGLE66OO2F6RYBXYSGR6A6UXVSB7JWSCJZY6YORSZ37UCBYKIBBR4J2TA",
    # Invalid lengths
    "TGKBRNX3LBNAL2I5ZAYSWFJWJ2Y2LRNZF7XXI4VZ5B34ITGWJBWH3XBR",
    "TGKBRNX3LBNAL2I5ZAYSWFJWJ2Y2LRNZF7XXI4VZ5B34ITGWJBWKYGD53QYQ",
]


#
# Tests
#
class AlgoAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(AlgoAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(AlgoAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(AlgoAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            AlgoAddrEncoder,
            {},
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AlgoAddr is AlgoAddrEncoder)
