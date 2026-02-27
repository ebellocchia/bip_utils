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
from bip_utils import TonAddr, TonAddrEncoder, TonAddrVersions
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00c6ba5594e3334ff890d2ab1dcf6757099b3505fd802d9ca1b4fc8b883f89a9de",
        "address_params": {
            "version": TonAddrVersions.V3R1,
        },
        "address": "UQCrT9wQSjIWfJIrWitT5dup79QzkHvKs8jWx_UOoKQlXvP_",
    },
    {
        "pub_key": b"00961411d8c9e817055fd615ad953cc0f87dad689ec23a1c48fc06e5472efecc55",
        "address_params": {
            "version": TonAddrVersions.V3R2,
        },
        "address": "UQB-ejjqwZvzd8m7fcZbPTofsRbGbuw96bQ190Lgi198e1Gl",
    },
    {
        "pub_key": b"00479a59b16b5fe57fa99dd763a3de0908cdc05d8a72f1ae1b535545dc6514e2ac",
        "address_params": {
            "version": TonAddrVersions.V4,
        },
        "address": "UQBhx8AhGyL7153Yaf8svkZkEKbG0JcsUcNpTwu2kOm5WaW7",
    },
    {
        "pub_key": b"1af97d53283a3c57f47db2b97263e86c93acc38853ca2246db5daa32cb7a1037",
        "address_params": {
            "version": TonAddrVersions.V4,
        },
        "address": "UQD3dn7-3QdJT_36TEL16JYWDz0tWqkNbuEKyOEjy0-1NbfG",
    },
    {
        "pub_key": b"1af97d53283a3c57f47db2b97263e86c93acc38853ca2246db5daa32cb7a1037",
        "address_params": {},   # Default: V4
        "address": "UQD3dn7-3QdJT_36TEL16JYWDz0tWqkNbuEKyOEjy0-1NbfG",
    },
    {
        "pub_key": b"ad724aba20a7591624efee55eae11ec1f765d483544a9bf42ff7467d0f88a113",
        "address_params": {
            "version": TonAddrVersions.V5R1,
        },
        "address": "UQB8E-CQxLds85ZPY8sXEYGe_EQ1qlY6q7l3BNbWQC1srNHe",
    },
]


#
# Tests
#
class TonAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(TonAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            TonAddrEncoder,
            {
                "version": TonAddrVersions.V4,
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_enc(
            TonAddrEncoder,
            {"version": 0},
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(TonAddr is TonAddrEncoder)
