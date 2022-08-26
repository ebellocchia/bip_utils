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
from bip_utils import XrpAddr, XrpAddrDecoder, XrpAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03db0da69187edd94aba300f1b2e7a09f407a8301d6fff54322a6ee4dde9842681",
        "address_dec": b"6d52060b65ae90a77e6d00b98ce4a3773767573d",
        "address_params": {},
        "address": "rwypvr27pYpzYQyDrFQBjDUhRDkHiecTHo",
    },
    {
        "pub_key": b"03333f37539bf526280cea9dda98758de4feb15910218e3e0a99ac17d1f5fac406",
        "address_dec": b"db05b585a44a1f3421facdf2aee1985c655513f2",
        "address_params": {},
        "address": "rLynFggnosDyDmoLzcgX6siu6X4yUBb36a",
    },
    {
        "pub_key": b"02553f6711f6ed3e1204dff91d9bf259ea01a2577dcc05383ce47f2cc5a98946bc",
        "address_dec": b"c2357c3ea1e67dd76dff6d8f470362c3e0fa86b3",
        "address_params": {},
        "address": "rJ6twS2cq28qMybswjQHb6BZK7kuwSFfZo",
    },
    {
        "pub_key": b"03530f281debbda165f54090b930c4467842231c3bd2e547d953444c7409ad4c20",
        "address_dec": b"21739c244b9ce0e243e8bc2686b2b94565cdd771",
        "address_params": {},
        "address": "rhs1osifPgg35Ff8pRk23vRtn6rhivVuTq",
    },
    {
        "pub_key": b"021cf750242895325d49efa12859369f7a45e9c3f5639172e4f2f5df4ae23301cf",
        "address_dec": b"17149e5478f9df3f45b3f6d33e21333943fc2b31",
        "address_params": {},
        "address": "rsfsErX3u9GRrMH1Nr6Qa4TAyWa53bx48D",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid net version
    "RGdwNmqegTAkWXoRparJCuCyEB1y91Dex",
    # Invalid checksum
    "rApB37YAWrhAnP5PbkgFYdtLjvAGTie8d",
    # Invalid length
    "rp9RDD4mjenCdVHjpdbf2wXyq32y8pJeV",
    "rnfSB6zbyZrJMgPEgkPFkidoc3VhNwy6mxS",
]


#
# Tests
#
class XrpAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(XrpAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(XrpAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(XrpAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            XrpAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(XrpAddr is XrpAddrEncoder)
