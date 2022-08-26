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
from bip_utils import EthAddr, EthAddrDecoder, EthAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03c41826497a000dd077b3becc10bea5765651c30c37e7bd63ed8562f919720126",
        "address_dec": b"4d46542bda7ff01f583e8459125c91d56d2426cf",
        "address_params": {},
        "address": "0x4d46542bdA7ff01f583e8459125c91D56D2426Cf",
    },
    {
        "pub_key": b"02d72bce774eb5d79384da08c3080ce3bd7996843a7f3efc008a5c45449aab3b0f",
        "address_dec": b"8c5f5279dd5a5dee331d629620fe6f3e7c73d21e",
        "address_params": {},
        "address": "0x8C5F5279DD5a5deE331d629620FE6f3e7c73d21e",
    },
    {
        "pub_key": b"027c323f3d80fa0c4891b3a36c3b2790cd04705bc8c66b79f356cc5c304d3eb45b",
        "address_dec": b"8bc53cd1c3ba83bd0d11f2f4bfe0819be8fb9794",
        "address_params": {},
        "address": "0x8BC53Cd1c3ba83bd0D11F2F4Bfe0819Be8fb9794",
    },
    {
        "pub_key": b"0226c4d55f5437ad010a6fb1cb6b7c37731a31516c77e5403af3b36fc80dfd2c59",
        "address_dec": b"a2ca1d082016421489b7891091ca1cf0d2d1220e",
        "address_params": {
            "skip_chksum_enc": True
        },
        "address": "0xa2ca1d082016421489b7891091ca1cf0d2d1220e",
    },
    {
        "pub_key": b"0261d015de607c9b8cfb77f658fabe6af3c7d6865740169026f2f2e95b6e5db14d",
        "address_dec": b"caab0bbedd3d903832053f4e21ccd6df48a66870",
        "address_params": {
            "skip_chksum_enc": True
        },
        "address": "0xcaab0bbedd3d903832053f4e21ccd6df48a66870",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "1x4d46542bdA7ff01f583e8459125c91D56D2426Cf",
    # Invalid checksum encoding
    "0x8C5F5279DD5a5deE331d629620Fe6f3e7c73d21E",
    # Invalid lengths
    "0xA2cA1D082016421489b7891091CA1CF0D2d1220",
    "0xA2cA1D082016421489b7891091CA1CF0D2d1220e1",
]


#
# Tests
#
class EthAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(EthAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(EthAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(EthAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            EthAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(EthAddr is EthAddrEncoder)
