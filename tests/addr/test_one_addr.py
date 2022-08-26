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
from bip_utils import OneAddr, OneAddrDecoder, OneAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03c4002dceb4728c2d66602fff93b75e65a61c0e933bdf15d2ba2add16a1069730",
        "address_dec": b"c9bb0fbd407f4634d93bea581f641587760efb7e",
        "address_params": {},
        "address": "one1exasl02q0arrfkfmafvp7eq4samqa7m7qe4lv6",
    },
    {
        "pub_key": b"0223f8e3d044ed176e016eba89f4ed936a0f8a1c4f01cc51de56c42d331717309c",
        "address_dec": b"2475002c2c983925b53fd6c7f94de91faeb8b680",
        "address_params": {},
        "address": "one1y36sqtpvnqujtdfl6mrljn0fr7ht3d5q5rtwf2",
    },
    {
        "pub_key": b"022f469a1b5498da2bc2f1e978d1e4af2ce21dd10ae5de64e4081e062f6fc6dca2",
        "address_dec": b"c497e3b751e8fba5753c0227d3cf13da44a008ca",
        "address_params": {},
        "address": "one1cjt78d63ara62afuqgna8ncnmfz2qzx2f4g0km",
    },
    {
        "pub_key": b"021c108820fc83a01e4380d50187dbe3ea889a4c18ad3cab6562e71438fa48bdfc",
        "address_dec": b"ad6dca466fa9f3922ee787fdeb147a78720334ef",
        "address_params": {},
        "address": "one144ku53n048eeyth8sl77k9r60peqxd803t4ml5",
    },
    {
        "pub_key": b"03f72613f6c9f2a7f20a2d59e32ae996e9b4e3c45b9bf772cf14e8f8bea1065abe",
        "address_dec": b"c44c58f65fa3f0d7135d8f503d86e89c3b41bac1",
        "address_params": {},
        "address": "one1c3x93ajl50cdwy6a3agrmphgnsa5rwkptdy0yj",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "ine1wj4nhg2k54aersyvjrgkv9js4sq74tajqxe3ej",
    # No separator
    "oneexasl02q0arrfkfmafvp7eq4samqa7m7qe4lv6",
    # Invalid checksum
    "one13ml09c5zxqgtn0quzgwn8xvx79qe5p4x04nmur",
    # Invalid encoding
    "one1exasl02q0brrfkfmafvp7eq4samqa7m7qe4lv6",
    # Invalid lengths
    "one1lmew9q3szzumc8qjr5eenph3gxdqdfszc5jv6",
    "one1rj80auhzsgcppwdursfp6vuesmc5rxsx5cuckdqn"
]


#
# Tests
#
class OneAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(OneAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(OneAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(OneAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            OneAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(OneAddr is OneAddrEncoder)
