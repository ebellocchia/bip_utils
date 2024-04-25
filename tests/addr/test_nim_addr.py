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
from bip_utils import NimAddr, NimAddrDecoder, NimAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"003ca0682d1a37a86759f7d945ef11af309f3c78e4b472ff2ab5175c76f4695536",
        "address_dec": b"766cc2f088792b66cedd499aae51f6a4749eac7a",
        "address_params": {},
        "address": "NQ66 ERNC 5U48 F4MN DKNV 96DA ULFN LHS9 VB3S",
    },
    {
        "pub_key": b"0081779fcb54fe4ecf3096d96067134f7d1657a25453a10014fc0501317dc43a49",
        "address_dec": b"6a91074766e2ed0189295e1d0cfd212cebe7d05f",
        "address_params": {},
        "address": "NQ48 DA8G EHT6 UBNG 3299 BQEG RY91 5KMX FL2Y",
    },
    {
        "pub_key": b"00906240ce5dfa27ff019f3cdab301c1aa3d4e1d50fcf6b66dc6149a83ceb78239",
        "address_dec": b"4684fde0b1aa021bad0caef0fba6df6dc80efd7f",
        "address_params": {},
        "address": "NQ59 8S2F TQ5H M811 PB8C MTQF P9NY DP40 VYBY",
    },
    {
        "pub_key": b"c5d6ebf3bd2dfcb1fb85a301bdb48b451e0d2dd9efcb91955b62f38d8430246e",
        "address_dec": b"472e9830e1e7fab5fa4583e02318cdbbf814b355",
        "address_params": {},
        "address": "NQ49 8UP9 GC71 UYVB BXJ5 GFG2 666D PFU1 9CSM",
    },
    {
        "pub_key": b"00e34b8f70f618d03ec7f2eaf19137ab2c2255039c2d54766be6ec56ebd0ca9d52",
        "address_dec": b"023426df75c9ff98d73be8c72eabbac5b6847251",
        "address_params": {},
        "address": "NQ34 08S2 DPTM R7YR HMRT V33J VAVS QNT8 8UJH",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "NW34 08S2 DPTM R7YR HMRT V33J VAVS QNT8 8UJH",
    # Invalid checksum
    "NQ35 08S2 DPTM R7YR HMRT V33J VAVS QNT8 8UJH",
    # Invalid encoding
    "NQ34 08S2 DPTM R7YR HM-T V33J VAVS QNT8 8UJH",
    # Invalid lengths
    "NQ34 08S2 DPTM R7YR HMRT V33J VAVS QNT8 8UJ",
    "NQ34 08S2 DPTM R7YR HMRT V33J VAVS QNT8 8UJHQ",
]


#
# Tests
#
class NimAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(NimAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(NimAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(NimAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            NimAddrEncoder,
            {},
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(NimAddr is NimAddrEncoder)
