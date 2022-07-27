# Copyright (c) 2022 Emanuele Bellocchia
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
import binascii
import unittest
from bip_utils import AdaByronAddrTypes, AdaByronAddrDecoder, AdaByronAddrEncoder, AdaByronAddr
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_ED25519_PUB_KEY, TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519KholawPublicKey

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0002b3add3c4ce78e2b4b671a2548182ecdbf92f7e82dfa0aba549b76cec1148f4",
        "address_dec": b"f8a3fb87d6853d699c4a116251c1053e461baf3ed926ad77b10aa53b",
        "address_params": {
            "chain_code": binascii.unhexlify(b"fa8397359cea983fe2195214e96b4d9f9bc31941d973a77d2d98ac77ea186db8"),
        },
        "address": "Ae2tdPwUPEZMchqp4zjkMo6R44DNT9rmh1KDK7AmRVXzG1mH3jWae217HWo",
    },
    {
        "pub_key": b"00582027a8f3ef4a324b5ee89e654a4ad151a3598b9a73dea55d8289a0edac9662",
        "address_dec": b"f27e98d1bc867bff78310d9e8cd4dedc438e269a93470bf5fde53e20",
        "address_params": {
            "chain_code": binascii.unhexlify(b"b378616c5e7fa932c7563a390b5404419691ba53b0e37917650870679e061479"),
            "addr_type": AdaByronAddrTypes.PUBLIC_KEY,
        },
        "address": "Ae2tdPwUPEZM18sAbkECJG9GxaRd2PMbaoxUjs5W7iUckiCGUSTMggRzLwt",
    },
    {
        "pub_key": b"0040aa8e5d4f812d5ee3dc28da1f19ed56aa57735c42c48dd99b5b30c130588f0e",
        "address_dec": b"2fd2ecc2c52a0b8f0b7c70f41ea989e52aab7654f1ce68d0ba84d3df",
        "address_params": {
            "chain_code": binascii.unhexlify(b"7f69a41a170714ca1d0ba84e33421301c7ad80e25f0c05d1d5910d422b063648"),
            "addr_type": AdaByronAddrTypes.PUBLIC_KEY,
        },
        "address": "Ae2tdPwUPEZ1aXoiiRE6CHf7d4zFL2PwtC5WV5E7Cp7Dfjr9J9cL3pwywRU",
    },
    {
        "pub_key": b"001e5525d1f12eb9b06343626610b54373d3e3b1c4e699d5b22740bacd3dc2088f",
        "address_dec": b"c342eab10589b628a75e5fd10366e5f2f45919e10180df4333a1d81b",
        "address_params": {
            "chain_code": binascii.unhexlify(b"f069f33174ba3117f4c6b0ee4b9fc568b0d6b17356a661f7210eca155f9a44ba"),
            "addr_type": AdaByronAddrTypes.PUBLIC_KEY,
        },
        "address": "Ae2tdPwUPEZGHncTxWxeGm1JbDsgfCicRupttizSDUAMrD81h1XNDqbXzE7",
    },
    {
        "pub_key": b"00c87eccc612c395b23f413adc06dd9547072af0d413fd11a0c17e6101d8c0467c",
        "address_dec": b"83287a391c6b3847c3d27117db11ae6922181140fcd638b01d3a32c9",
        "address_params": {
            "chain_code": binascii.unhexlify(b"34db859ba3294c2fa2c130587516f77f04cf70925c01e8f4cd5f34f7ba5b67a0"),
            "addr_type": AdaByronAddrTypes.REDEMPTION,
        },
        "address": "Ae2tdPwUPEZ9tojGU84oHw8578UURrhGEiRKtAoExUJy9mrxJTdffEvyZ93",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid address payload
    "5oP9ib5MUEWuUNJXSjyUWvimrYdUUyzKrPP3mMfKp4VFw4MbAHGVjEuXPqaqjp5gG3",
    "jYTLseJK1m1pwWvmyNgRB6m5oqJ68BYe1nqw4Hb4Q1gYdC7kL7fdxVaRJuSK",
    # Invalid CRC
    "Ae2tdPwUPEZ1RPUDa1v5RpwafGhMWppE19i3Y5sAgKknTHKw6UrvRNcdL6D",
    # Invalid CBOR tag
    "3BesdaTS8reTfZA7DiKfpzLxepvPGHzChBytguQqeXfTWV9FQePhgahXgA",
    # Invalid CBOR encoding
    "Ae2tr7hYAE9LJU98dz6iHoDNozJq3EvtavT1eViVsMrVmtTiJ81sT7UgzZm",
    # Invalid address type
    "Ae2tdPwUPEZEReKzM7B6t4iLeSLkL4gZtE4G7Pvc3tZVcyaNmsX589QjDSX",
    # Invalid lengths
    "3Bf3BWfUXmSDiwn4LNDEAZJ4TWtvjubuo2FGMyrR5BxoAopTRDy7eFDAp2",
    "jYTLseJK1m4sWU7ba8ryVbZ2FwAoYyRAyPTxKLMiQ3wtR7XaEJ6pYZ1cAyY9",
]


#
# Tests
#
class AdaByronAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, AdaByronAddrEncoder, Ed25519KholawPublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        AddrBaseTestHelper.test_decode_addr(self, AdaByronAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        AddrBaseTestHelper.test_invalid_dec(
            self,
            AdaByronAddrDecoder,
            {
                "chain_code": binascii.unhexlify(b"f069f33174ba3117f4c6b0ee4b9fc568b0d6b17356a661f7210eca155f9a44ba"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(
            self,
            AdaByronAddrEncoder,
            {
                "chain_code": binascii.unhexlify(b"f069f33174ba3117f4c6b0ee4b9fc568b0d6b17356a661f7210eca155f9a44ba"),
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        AddrBaseTestHelper.test_invalid_params_enc(
            self,
            AdaByronAddrEncoder,
            TEST_ED25519_PUB_KEY,
            {
                "chain_code": b"",
            },
            ValueError
        )
        AddrBaseTestHelper.test_invalid_params_enc(
            self,
            AdaByronAddrEncoder,
            TEST_ED25519_PUB_KEY,
            {
                "chain_code": binascii.unhexlify(b"f069f33174ba3117f4c6b0ee4b9fc568b0d6b17356a661f7210eca155f9a44ba"),
                "addr_type": 0,
            },
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AdaByronAddr is AdaByronAddrEncoder)
