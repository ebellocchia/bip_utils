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
from bip_utils import TrxAddr, TrxAddrDecoder, TrxAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"033d77bf3f63edd7aad3163c6f04eb48e968a76c3043def375c21a8414675e11ae",
        "address_dec": b"2b6e3782fbedade9e4c05078f46a9e29841f0bbe",
        "address_params": {},
        "address": "TDvr6Jpwfp1wDiV7PhaB19YMsMHRSXmY7p",
    },
    {
        "pub_key": b"03436c3e77f7738dcbfc2cfbb6e12e1509979cde41f216eed86c82ab661b5b3fc0",
        "address_dec": b"e9e9d3001799a9fa785bed8cf3a7995e8aebb8bd",
        "address_params": {},
        "address": "TXJ2Z9VAwDpQ4W6zwTpXxRUpwFVDetPQuC",
    },
    {
        "pub_key": b"02f6cd3a2761360cd7e8c183aca501ee0ce0e42fc270a68aafd153dd06c857a8c4",
        "address_dec": b"8ae776b9997f92f90a25a156423918e751496db5",
        "address_params": {},
        "address": "TNdfXv6WTTyS2ohkTu8YA62WmLTNWqK46i",
    },
    {
        "pub_key": b"0360e11323f918ade5a53bd5ac7171712f019f62e9ad8e0e18ec2b8ca01d4daba4",
        "address_dec": b"386fd4b1ad845ca6495e45544acf2b32f25f45d2",
        "address_params": {},
        "address": "TF7cowibxyJdMyGtjP2yP7oyN5ZmSMPnWd",
    },
    {
        "pub_key": b"034767fb943ddb893377754ba71e4f82ec15134c7fe4240529d3d0ff473650b210",
        "address_dec": b"f616473322599b7cb664e438e7264dbb06996336",
        "address_params": {},
        "address": "TYQPvAG6AuzQed8RPuH62pcbZBKj9TkPk1",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "T94nw3xoTjXXqBzLNUwmYhLovg4nNVZKB6",
    # Invalid checksum
    "TLc6WnRN9DxA4uygPrHGr9A1DhVMxx2w45",
    # Invalid lengths
    "6w9cP3taF7zAsCtmViHprBoiiK68GnrsC",
    "319DKUdrbDY8tXmD2xWfQW5aJ3akX7ytypnG",
]


#
# Tests
#
class TrxAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(TrxAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(TrxAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(TrxAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            TrxAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(TrxAddr is TrxAddrEncoder)
