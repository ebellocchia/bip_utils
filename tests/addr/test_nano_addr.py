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
from bip_utils import NanoAddr, NanoAddrDecoder, NanoAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_BLAKE2B_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519Blake2bPublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0063b14c2b966809da4b4f90c53ee12633be9f708cbd834eb24012f9306f3e8f4a",
        "address_dec": b"63b14c2b966809da4b4f90c53ee12633be9f708cbd834eb24012f9306f3e8f4a",
        "address_params": {},
        "address": "nano_1rxjbioset1bub7nz6879uikeexymxrashe5bts616qs83qmx5tcxoeox6ms",
    },
    {
        "pub_key": b"0089624c7666f0b8004df74ef749a96991bb602273b41fec38e7190fcd2ebcb5f9",
        "address_dec": b"89624c7666f0b8004df74ef749a96991bb602273b41fec38e7190fcd2ebcb5f9",
        "address_params": {},
        "address": "nano_34d4bju8fw7r138zgmqqb8npm6fue1j99f1zxiwgg8ahsnqdsfhsr6dyoimk",
    },
    {
        "pub_key": b"006bfef755481c161fcd56c7b7902193528a36b117563793cf02a374455e983dcf",
        "address_dec": b"6bfef755481c161fcd56c7b7902193528a36b117563793cf02a374455e983dcf",
        "address_params": {},
        "address": "nano_1tzyyxcni91p5z8ofjxqk1is8nnc8trjgojqkh9i7aunaohbihghw4edxiqj",
    },
    {
        "pub_key": b"8f3330f2d62eb3232b4d23d67193d37d9c61678d12445cc68620e0f648456788",
        "address_dec": b"8f3330f2d62eb3232b4d23d67193d37d9c61678d12445cc68620e0f648456788",
        "address_params": {},
        "address": "nano_35sm85sfedom6eontaypg8bx8zewe7mrt6k6dm5aea91ys66cswa9bw9bg5f",
    },
    {
        "pub_key": b"1594ba7eecada3f311d52d84bc462a8398f4aac71d252cd4db79e946d5511f0d",
        "address_dec": b"1594ba7eecada3f311d52d84bc462a8398f4aac71d252cd4db79e946d5511f0d",
        "address_params": {},
        "address": "nano_17enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfwgzbact6",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "neno_1rxjbioset1bub7nz6879uikeexymxrashe5bts616qs83qmx5tcxoeox6ms",
    # Invalid encoding
    "nano_1rxjbi0set1bub7nz6879uikeexymxrashe5bts616qs83qmx5tcxoeox6ms",
    # Invalid checksum
    "nano_17enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfaiosbhq5",
    # Invalid lengths
    "nano_7enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfwgzbact6",
    "nano_117enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfwgzbact6",
]


#
# Tests
#
class NanoAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(NanoAddrEncoder, Ed25519Blake2bPublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(NanoAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(NanoAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            NanoAddrEncoder,
            {},
            TEST_ED25519_BLAKE2B_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(NanoAddr is NanoAddrEncoder)
