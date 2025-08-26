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
from bip_utils import MvrkAddr, MvrkAddrDecoder, MvrkAddrEncoder, MvrkAddrPrefixes
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00c984cd868dae74bc8879ed6079c53cfb328e0bc095a1d587c26c4d79bdb4f354",
        "address_dec": b"6e305f9f45dee7923733ecdfd31abd949c045ec3",
        "address_params": {
            "prefix": MvrkAddrPrefixes.MV1,
        },
        "address": "mv1J48Gs3LfajJ5tycqv9i7rxy1eJkZbx894",
    },
    {
        "pub_key": b"00ade94377eb07a7f406937c4b0e1aa6e64f78ba0e9faa3fbe43386a5a20f79804",
        "address_dec": b"b1b571e3849857bc8624ab77af0f20c86e2e1037",
        "address_params": {
            "prefix": MvrkAddrPrefixes.MV1,
        },
        "address": "mv1QD8xgAEiuczjEPAfNmgpvdLQtZJw22f6W",
    },
    {
        "pub_key": b"003dad9044f1eec4b981fbdb8f0a3128c62d6f64dde84220a0c5aba12711224f45",
        "address_dec": b"96b068eeb0f66d11b7baaaa4abd20ea84c429167",
        "address_params": {
            "prefix": MvrkAddrPrefixes.MV1,
        },
        "address": "mv1MkGgfDBjWs8nwUvNSSkPGHu1BmyNiwbzf",
    },
    {
        "pub_key": b"2ae8dfda6cfa73f759a84a328c0f1003541adf647e2d85f6c8c8f42f7045e217",
        "address_dec": b"b8925de806f0010e74ffd70695e2d3e50d6110fa",
        "address_params": {
            "prefix": MvrkAddrPrefixes.MV1,
        },
        "address": "mv1QqRfkcPgHKvkxxstfJLWfzrcPww2VGPVD",
    },
    {
        "pub_key": b"804e68f00f2a25fe4abc55022757de59604c874f91cc0fb60da580ad4481992f",
        "address_dec": b"1e31ade32e8045b4d611ae777a0bb87b521236b4",
        "address_params": {
            "prefix": MvrkAddrPrefixes.MV1,
        },
        "address": "mv1Am9nEu2f1nPGnkBtcEczja9gQYAysmZAy",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "mv2MRgV25jZFkzmz5YMii22HmCUKJRjEC1Cy",
    # Invalid checksum
    "mv1NjF5pi9ps7dBkeKfCQH8dZwEGyhweUkpu",
    # Invalid encoding
    "mv1Ge4fZQiycoZ6bQqKq175KKNYEru2kLuwB",
    # Invalid lengths
    "Cn68Z22gs5gPejzt14wjig8TUFfNXvu8dSb",
    "4xSdJ6eLyZEBLy5wsYoj9b6ahbtGgKQaBvjrGy",
]


#
# Tests
#
class MvrkAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(MvrkAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(MvrkAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            MvrkAddrDecoder,
            {
                "prefix": MvrkAddrPrefixes.MV1,
            },
            TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            MvrkAddrEncoder,
            {
                "prefix": MvrkAddrPrefixes.MV1,
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            MvrkAddrDecoder,
            {"prefix": 0},
            TypeError
        )
        self._test_invalid_params_enc(
            MvrkAddrEncoder,
            {"prefix": 0},
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(MvrkAddr is MvrkAddrEncoder)
