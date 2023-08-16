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
from bip_utils import InjAddr, InjAddrDecoder, InjAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"032efb910c36fe004c7241efd61867c0e793847cb738f44bec5d941ceaeb62d8ad",
        "address_dec": b"d88112279bcc2d45430aa0853c5788a9570a6f2b",
        "address_params": {},
        "address": "inj1mzq3yfumesk52sc25zznc4ug49ts5met4w3hal",
    },
    {
        "pub_key": b"03e9338019f89973be2e30702f33221aa747560ef888fbceb31b78e48a0b2e4468",
        "address_dec": b"8a82c82138ad57474a1336b9f572c306740c0c55",
        "address_params": {},
        "address": "inj132pvsgfc44t5wjsnx6ul2ukrqe6qcrz4x4hag0",
    },
    {
        "pub_key": b"02e333d723d596d801149e9b93907e7575be95a30ff626fa218c65e540ca0b4a4e",
        "address_dec": b"ab1c6eeb2cfef52ccf69f2a117457d4024217ea8",
        "address_params": {},
        "address": "inj14vwxa6evlm6jenmf72s3w3tagqjzzl4gngxn43",
    },
    {
        "pub_key": b"025a4866f35a92c6063233630acc91b5a9e8e323c2096fe248b383f677d1cb8e3d",
        "address_dec": b"a3e2e37ced8b421db8b0929dc1f7e1ad7a0b0747",
        "address_params": {},
        "address": "inj1503wxl8d3dppmw9sj2wuralp44aqkp68de0j4t",
    },
    {
        "pub_key": b"02f2e5778c6cde8acdd53bca9b9b3c64969d6311ae9057928931f658f919f57779",
        "address_dec": b"a7cbba9e9be24059b8ad14f30d1928fa7ee8098f",
        "address_params": {},
        "address": "inj15l9m485mufq9nw9dznes6xfglflwszv0935dkx",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "ini19pzn0a3zdf0mw5rmfmv63cna045wywgaqpc3pz",
    # No separator
    "inj5l9m485mufq9nw9dznes6xfglflwszv0935dkx",
    # Invalid checksum
    "inj15l9m485mufq9nw9dznes6xfglflwszv0935dky",
    # Invalid encoding
    "inj15l9m485mubq9nw9dznes6xfglflwszv0935dkx",
    # Invalid lengths
    "inj1cs877t9a4a09h3703dgavj5rupd3m9gds55xp",
    "inj18lltlngecd78fmuu72sl85ydajerndcsqqeyz3za",
]


#
# Tests
#
class InjAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(InjAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(InjAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(InjAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            InjAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(InjAddr is InjAddrEncoder)
