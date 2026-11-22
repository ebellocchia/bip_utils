# Copyright (c) 2026 Emanuele Bellocchia
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

from bip_utils import Bech32ChecksumError, NostrNsecDecoder, NostrNsecEncoder, Secp256k1PrivateKey
from tests.ecc.test_ecc import (
    TEST_ED25519_BLAKE2B_PRIV_KEY,
    TEST_ED25519_PRIV_KEY,
    TEST_NIST256P1_PRIV_KEY,
    TEST_SR25519_PRIV_KEY,
    TEST_VECT_SECP256K1_PRIV_KEY_INVALID,
)


# Test vectors from NIP-19, NIP-06 and BIP-0085 (Nostr application)
TEST_VECT = [
    {
        "key_bytes": b"67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
        "encode": "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
    },
    {
        "key_bytes": b"7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
        "encode": "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp",
    },
    {
        "key_bytes": b"c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
        "encode": "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
    },
    {
        "key_bytes": b"ff6eb0fcdf1ef87a2a06b0d7884d495b486d0faa210e9f80f23fd649d6e114d2",
        "encode": "nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz",
    },
]

# Tests for invalid checksum
TEST_VECT_DEC_CHKSUM_INVALID = [
    "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfeq",
    # Bech32m instead of bech32
    "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laq9009uk",
]

# Tests for invalid encodings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "npub1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqu95glp",
    # No separator
    "nsecvl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
    # Invalid encoding
    "nsec1vl029bgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
    # Invalid lengths
    "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9u7jpluy",
    "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqqx7ppqj",
    # Invalid private keys (zero and curve order)
    "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwkhnav",
    "nsec1lllllllllllllllllllllllll6a2ah8x4ay2qwal6f0ge5pkg9qstu3zum",
]


#
# Tests
#
class NostrNsecTests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECT:
            self.assertEqual(test["key_bytes"], binascii.hexlify(NostrNsecDecoder.Decode(test["encode"])))

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["key_bytes"])

            self.assertEqual(test["encode"], NostrNsecEncoder.Encode(key_bytes))
            self.assertEqual(test["encode"], NostrNsecEncoder.Encode(Secp256k1PrivateKey.FromBytes(key_bytes)))

    # Test invalid checksum for decoding
    def test_dec_invalid_checksum(self):
        for test in TEST_VECT_DEC_CHKSUM_INVALID:
            # "with" is required because the exception is raised by Bech32 module
            with self.assertRaises(Bech32ChecksumError):
                NostrNsecDecoder.Decode(test)

    # Test invalid encodings for decoding
    def test_dec_invalid(self):
        for test in TEST_VECT_DEC_INVALID:
            self.assertRaises(ValueError, NostrNsecDecoder.Decode, test)

    # Test invalid keys for encoding
    def test_enc_invalid_keys(self):
        self.assertRaises(TypeError, NostrNsecEncoder.Encode, TEST_ED25519_PRIV_KEY)
        self.assertRaises(TypeError, NostrNsecEncoder.Encode, TEST_ED25519_BLAKE2B_PRIV_KEY)
        self.assertRaises(TypeError, NostrNsecEncoder.Encode, TEST_NIST256P1_PRIV_KEY)
        self.assertRaises(TypeError, NostrNsecEncoder.Encode, TEST_SR25519_PRIV_KEY)

        for test in TEST_VECT_SECP256K1_PRIV_KEY_INVALID:
            self.assertRaises(ValueError, NostrNsecEncoder.Encode, binascii.unhexlify(test))
