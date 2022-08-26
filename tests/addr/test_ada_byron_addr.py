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

from bip_utils import (
    AdaByronAddrDecoder, AdaByronAddrTypes, AdaByronIcarusAddr, AdaByronIcarusAddrEncoder, AdaByronLegacyAddr,
    AdaByronLegacyAddrEncoder, Bip32ChainCode, Bip32PathError, Bip32PathParser, ChaCha20Poly1305
)
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519KholawPublicKey


# Some random public keys for Icarus addresses
TEST_VECT_ICARUS_ADDRESS = [
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
]

# Some random public keys for legacy addresses
TEST_VECT_LEGACY_ADDRESS = [
    {
        "pub_key": b"00f286b12bacea7be1a19d581bd573bdc82e8410b98c3a70485b6d6eeb5e88028e",
        "address_dec": b"4617109fadd39396b981833f3694fc8e60658cbcc2a40d831e43c00b140539c64edded60a7f2d46967d90757466da40a8148314d69bf00d2",
        "address_params": {
            "chain_code": binascii.unhexlify(b"00857e69a9598ab4db1346586f8f2c9440f61ccaca62ed36182b9f26fef4a9dd"),
            "hd_path": "m/0'/0'",
            "hd_path_key": binascii.unhexlify(b"c582f8e7cf7aeb6e5f3e96e939a92ae1642360a51d45150f34e70132a152203f"),
        },
        "address": "DdzFFzCqrhsnx5973UzwoEcQ7cN3THD9ZQZvbVd5srhrPoECSt1WUTrQSR8YicSnH3disaSxQPcNMUEC7XNuFxRd8jCAKVXLne3r29xs",
    },
    {
        "pub_key": b"00e3a0ead2f426454f27333daa12e536d1e67ffa3fffd407ab820ab4d77206416e",
        "address_dec": b"cd55975d48fa6a028739c85c24ebde614881f34efc073ee44b6ba13948d101da467d6c6931946f28f23594344eb09ca5b3c7961b452b11c3",
        "address_params": {
            "chain_code": binascii.unhexlify(b"a033015fa18212c2d825137b7565c6992cd1ba6f97f62b369849ca0ee950170e"),
            "hd_path": Bip32PathParser().Parse("m/0'/1'"),
            "hd_path_key": binascii.unhexlify(b"c7e8888175933d3a3a7ef3d1170024d33b4aaf256d7a54483895af99e053d1fc"),
        },
        "address": "DdzFFzCqrht6eK5MiHwersYzjc1eCeE6xNmc2goLk3d3DnHjSNUgAh8gQdNLD3263mN21Dv2DYKrEy2v5GXGwLDGNNrfdGvjxDkEKG5y",
    },
    {
        "pub_key": b"00f8afc628fab5cd1670a3c06199f8f5f5a23ccfe70668a77a57a289bc86c1e981",
        "address_dec": b"12ec070b007c8467e54cffa490d7094be089f970c3e067bcc7cd8ef1bd1e942a881aa4dfb113a02c63f72b1bda54de2c822751d492b068b5",
        "address_params": {
            "chain_code": binascii.unhexlify(b"f0c7e9ff5fb34273895ff3e2bd3c33e7a63ee9c1cba0a476e92bb9dc43d9feda"),
            "hd_path": Bip32PathParser().Parse("m/0'/0'"),
            "hd_path_key": binascii.unhexlify(b"330a021bdd25ee1d09d7ebd8fc326b8e9f716920df4483bba16e7d71002d83eb"),
            "addr_type": AdaByronAddrTypes.PUBLIC_KEY,
        },
        "address": "DdzFFzCqrhsgFohKpmf6o9hzVLL48GzVnMwVk5StRj6cxKXHqkhbgxMsXwZNr7aPD5pEyDHbrDzwGPpUBuYdikjLtQtHtDFmJqXxBuXH",
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
    "Ae2tr7hYAE9LJU98dz6iHoDNozJq3EvtavT1eViVsMrVmtTiJ81sT7UgzZm",
    # Invalid address type
    "Ae2tdPwUPEZEReKzM7B6t4iLeSLkL4gZtE4G7Pvc3tZVcyaNmsX589QjDSX",
    # Invalid address attributes
    "DdzFFzCqrhsgTQrapUXd8JB5ELH8EBkvCPz2EnRxJTjJ5pqjGRk4wAS1FGJBfZ99xJdyn57kyxvztCUMwN3ZvRPLsozJYRrGbJqXowcF",
    # Invalid lengths
    "3Bf3BWfUXmSDiwn4LNDEAZJ4TWtvjubuo2FGMyrR5BxoAopTRDy7eFDAp2",
    "jYTLseJK1m4sWU7ba8ryVbZ2FwAoYyRAyPTxKLMiQ3wtR7XaEJ6pYZ1cAyY9",
]


#
# Tests
#
class AdaByronAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(AdaByronIcarusAddrEncoder, Ed25519KholawPublicKey, TEST_VECT_ICARUS_ADDRESS)
        self._test_encode_key(AdaByronLegacyAddrEncoder, Ed25519KholawPublicKey, TEST_VECT_LEGACY_ADDRESS)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(AdaByronAddrDecoder, TEST_VECT_ICARUS_ADDRESS)
        self._test_decode_addr(AdaByronAddrDecoder, TEST_VECT_LEGACY_ADDRESS)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            AdaByronAddrDecoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            AdaByronIcarusAddrEncoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )
        self._test_invalid_keys(
            AdaByronLegacyAddrEncoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
                "hd_path": "m/0'/0'",
                "hd_path_key": b"\x00" * ChaCha20Poly1305.KeySize(),
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            AdaByronAddrDecoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
                "addr_type": 0,
            },
            TypeError
        )
        self._test_invalid_params_enc(
            AdaByronIcarusAddrEncoder,
            {
                "chain_code": b"\x00" * (Bip32ChainCode.FixedLength() - 1),
            },
            ValueError
        )
        self._test_invalid_params_enc(
            AdaByronLegacyAddrEncoder,
            {
                "chain_code": b"\x00" * (Bip32ChainCode.FixedLength() - 1),
                "hd_path": "m/0'/0'",
                "hd_path_key": b"\x00" * ChaCha20Poly1305.KeySize(),
            },
            ValueError
        )
        self._test_invalid_params_enc(
            AdaByronLegacyAddrEncoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
                "hd_path": "m/0'/0'",
                "hd_path_key": b"\x00" * (ChaCha20Poly1305.KeySize() - 1),
            },
            ValueError
        )
        self._test_invalid_params_enc(
            AdaByronLegacyAddrEncoder,
            {
                "chain_code": b"\x00" * Bip32ChainCode.FixedLength(),
                "hd_path": "m/a/0'",
                "hd_path_key": b"\x00" * (ChaCha20Poly1305.KeySize() - 1),
            },
            Bip32PathError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AdaByronLegacyAddr is AdaByronLegacyAddrEncoder)
        self.assertTrue(AdaByronIcarusAddr is AdaByronIcarusAddrEncoder)
