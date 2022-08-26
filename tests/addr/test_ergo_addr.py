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
from bip_utils import ErgoNetworkTypes, ErgoP2PKHAddr, ErgoP2PKHAddrDecoder, ErgoP2PKHAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"02ea9dca6f20d96eaa2ac8d16d22f36e08858f0ea8589784303c5943dd35248461",
        "address_dec": b"02ea9dca6f20d96eaa2ac8d16d22f36e08858f0ea8589784303c5943dd35248461",
        "address_params": {},
        "address": "9gJPUXCkiE7GDwcKMpFfixaGxoHMreUb2JAYKzrvLe3h2ZEnW5G",
    },
    {
        "pub_key": b"02b471290cd37ad4e07738f904f56bf0be15852aede0a9200934b2a368296bca9d",
        "address_dec": b"02b471290cd37ad4e07738f904f56bf0be15852aede0a9200934b2a368296bca9d",
        "address_params": {},
        "address": "9ftXfVsBW1hUb3F432NEYqMgBfPgW4UsTgsFo6ofEsXyMx2rzL7",
    },
    {
        "pub_key": b"032cad0ddc6269283303b5af5826df4baab49c01d2a7799d97079efa9be22868d7",
        "address_dec": b"032cad0ddc6269283303b5af5826df4baab49c01d2a7799d97079efa9be22868d7",
        "address_params": {},
        "address": "9goUsybeXWFiSR5tW51M5MuHXt4h9Ku5hk5UVgre3y9tsUULjXU",
    },
    {
        "pub_key": b"03a9e135bc31dec8399b8975ef3d7b52221e8e7b0cf581739be29885d2b3e40589",
        "address_dec": b"03a9e135bc31dec8399b8975ef3d7b52221e8e7b0cf581739be29885d2b3e40589",
        "address_params": {
            "net_type": ErgoNetworkTypes.MAINNET
        },
        "address": "9hkd3LJwbJKwiBFnfy8QUE8ULRasFpVTD1Yw2TTq2YruqtYAoYa",
    },
    {
        "pub_key": b"022b6e95c3f5221f22d2b5d2259b65b79e923bd405870535921884ec40f646e060",
        "address_dec": b"022b6e95c3f5221f22d2b5d2259b65b79e923bd405870535921884ec40f646e060",
        "address_params": {
            "net_type": ErgoNetworkTypes.TESTNET
        },
        "address": "3WvwLWTKDWHkYLYSszeGxoxsnegkrCSb972EsjGDz9wfvsdzqxYA",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "JEDAQL63FbvNggDwEyyhQrufXMfYofeAygKYC7qwgj6LR1UorUU",
    # Invalid checksum
    "9hM6Fs3kV2FiG6pgNtYQmsd6uaejrQQCDoFCWmTYHxZfa58fJ6s",
    # Invalid public key
    "9ev5A1hHZsdNaDp1CVwtuMp7Pmj8ijcV7Nw91AJyxFsa4C4fzUP",
    # Invalid lengths
    "2yT6zeBNY6V6Q8i5MvnCSCxroCkamwckKJetNe8C7Bd5HJ3EpQ",
    "fApd1KNP3jsUrbmY5s3PQRNeJ1gDtzQrSZsbp651CbPcg5WoLEdM",
]


#
# Tests
#
class ErgoAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(ErgoP2PKHAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(ErgoP2PKHAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(ErgoP2PKHAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            ErgoP2PKHAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            ErgoP2PKHAddrDecoder,
            {
                "net_type": 0,
            },
            TypeError
        )
        self._test_invalid_params_enc(
            ErgoP2PKHAddrEncoder,
            {
                "net_type": 0,
            },
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(ErgoP2PKHAddr is ErgoP2PKHAddrEncoder)
