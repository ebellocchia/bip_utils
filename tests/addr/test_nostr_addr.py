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
from bip_utils import NostrAddr, NostrAddrDecoder, NostrAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Test vectors from NIP-19 and NIP-06:
# https://github.com/nostr-protocol/nips/blob/master/19.md
# https://github.com/nostr-protocol/nips/blob/master/06.md
TEST_VECT = [
    {
        "pub_key": b"027e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "address_dec": b"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "address_params": {},
        "address": "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    },
    # Same X coordinate with odd Y, it shall result in the same address
    {
        "pub_key": b"037e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "address_dec": b"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "address_params": {},
        "address": "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    },
    {
        "pub_key": b"023bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "address_dec": b"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "address_params": {},
        "address": "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
    },
    {
        "pub_key": b"0217162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
        "address_dec": b"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
        "address_params": {},
        "address": "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
    },
    {
        "pub_key": b"02d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
        "address_dec": b"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
        "address_params": {},
        "address": "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "nsec10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qw6eqda",
    # No separator
    "npub0elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    # Invalid checksum
    "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptq",
    # Invalid checksum (bech32m instead of bech32)
    "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qhszdw2",
    # Invalid encoding
    "npub10elfcb4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    # Invalid public key
    "npub1xslangc9gttesyrdu8z6vt2yq0y27lyy9cgm4hzh35s74085kknqhd39h7",
    # Invalid lengths
    "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dmup82t8f",
    "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qqlhqg6v",
]


#
# Tests
#
class NostrAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(NostrAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(NostrAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(NostrAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            NostrAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(NostrAddr is NostrAddrEncoder)
