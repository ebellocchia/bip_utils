# Copyright (c) 2023 Emanuele Bellocchia
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
from bip_utils import SuiAddr, SuiAddrDecoder, SuiAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0046ec4d3aaab1bacfb1b2efe89db4da5a44c471ae458ae219cd6523c5e9d78f21",
        "address_dec": b"c94486e9d364391964952ffe820a7e4c224a2065675f24166ffc3fa300dec922",
        "address_params": {},
        "address": "0xc94486e9d364391964952ffe820a7e4c224a2065675f24166ffc3fa300dec922",
    },
    {
        "pub_key": b"002dfa84adaee72fb91cacb42f2461d50ab0c676b8f16cc657f30a71409e70a499",
        "address_dec": b"7b4c35fe88a47ccc3604e1f8ff90ee54e2ceba6556e63882a21ecc26fdd176c6",
        "address_params": {},
        "address": "0x7b4c35fe88a47ccc3604e1f8ff90ee54e2ceba6556e63882a21ecc26fdd176c6",
    },
    {
        "pub_key": b"00a444a62117dcaa27e644b66167104091d1d19526bf9c25b3f561b0db0c97866d",
        "address_dec": b"9b458e26f2d0445e25512e0151d79002c5fe8dadfb8dffd0de89a2960a160271",
        "address_params": {},
        "address": "0x9b458e26f2d0445e25512e0151d79002c5fe8dadfb8dffd0de89a2960a160271",
    },
    {
        "pub_key": b"d87d2323202e11222168603e2bf4752d2719919366579ff6fafe66cc01787cd2",
        "address_dec": b"adde5c6decefdd44140e6f4fb55a1128378a36cdce770d86f9b93d74f0fd733c",
        "address_params": {},
        "address": "0xadde5c6decefdd44140e6f4fb55a1128378a36cdce770d86f9b93d74f0fd733c",
    },
    {
        "pub_key": b"b3d59aaa0324fe0d9abcd9c380520374909186cf35e8b50998c689611945d98e",
        "address_dec": b"dbab0542986aff6e2fe307f0713e124722e9705a5d36574167369b92790eb389",
        "address_params": {},
        "address": "0xdbab0542986aff6e2fe307f0713e124722e9705a5d36574167369b92790eb389",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "00adde5c6decefdd44140e6f4fb55a1128378a36cdce770d86f9b93d74f0fd733c",
    # Invalid lengths
    "0xadde5c6decefdd44140e6f4fb55a1128378a36cdce770d86f9b93d74f0fd733",
    "0xadde5c6decefdd44140e6f4fb55a1128378a36cdce770d86f9b93d74f0fd733cd",
]


#
# Tests
#
class SuiAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(SuiAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(SuiAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(SuiAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            SuiAddrEncoder,
            {},
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(SuiAddr is SuiAddrEncoder)
