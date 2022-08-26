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
from bip_utils import EosAddr, EosAddrDecoder, EosAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0290ae9e1951967ea073b242c4e6dba5e728d9f4dca4a7161e1ec7f22114cd72c4",
        "address_dec": b"0290ae9e1951967ea073b242c4e6dba5e728d9f4dca4a7161e1ec7f22114cd72c4",
        "address_params": {},
        "address": "EOS5zD4eXtvBmLhzmj9CtvuG2wxwuKcTbYxYwsGpPvKe68ExHjJsc",
    },
    {
        "pub_key": b"03f0c00e0faa983a664b526a3c9fc09362ac1a200159a021ce2ffe07d7938ff725",
        "address_dec": b"03f0c00e0faa983a664b526a3c9fc09362ac1a200159a021ce2ffe07d7938ff725",
        "address_params": {},
        "address": "EOS8fGAt3L5oXQeXwnZDpWvXeipNi8FcrfUbL79TiD55za9CZo3pr",
    },
    {
        "pub_key": b"0381c6e21d718774ec71acf702b2f4a4df93ff680096840ad47c0487bd595ecc65",
        "address_dec": b"0381c6e21d718774ec71acf702b2f4a4df93ff680096840ad47c0487bd595ecc65",
        "address_params": {},
        "address": "EOS7pPWL22sB1tbTkec6zDsSW2GpNE6faQzQJJ9CGc7CC1Q9FQ8r2",
    },
    {
        "pub_key": b"03771a273de43fd0e01ce40dfbb6fe487d0cc88caad8e3af6e3865d39acf534ad3",
        "address_dec": b"03771a273de43fd0e01ce40dfbb6fe487d0cc88caad8e3af6e3865d39acf534ad3",
        "address_params": {},
        "address": "EOS7jgqNtYBCGb4fLDFepiBBxFbpcEPTXCKLihH9GtKf4QiGcV2Xo",
    },
    {
        "pub_key": b"03c2623b9c450d7e5c16c02b41a34b7eff782481a52d99060c8e6e6188e154a98a",
        "address_dec": b"03c2623b9c450d7e5c16c02b41a34b7eff782481a52d99060c8e6e6188e154a98a",
        "address_params": {},
        "address": "EOS8JqoRy3T3ok9cN2WtcPkFDYowcpNTtwBs951NLxN56857KDHXa",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "EAS5zD4eXtvBmLhzmj9CtvuG2wxwuKcTbYxYwsGpPvKe68ExHjJsc",
    # Invalid checksum
    "EOS8JqoRy3T3ok9cN2WtcPkFDYowcpNTtwBs951NLxN5685CU8jMo",
    # Invalid encoding
    "EOS7jgqNtYBCGb4fLDFepiBBxFbpcEPTXCKLihH9GtKf4QiGcV2X0",
    # Invalid public key
    "EOS1xDQ9DtsmxpSaTECu82Hpz7qd324jjMHcB8urMxy9R5mFNVYaw",
    "EOS5HVzeo7QxVQ4D3T8746jGKrxa5JJTtKfkoaYpDVUWAHj51NWwn",
    # Invalid lengths
    "EOS2Y997vhCZrH3xKtBnzKqfU4XoeRUP32xdLb8Yb8h8MDk4gFMH",
    "EOSWwbSdNcVaCnKSh4wkEg5o5ZvuesCkR72d88bdupWFQRs7fPsFP2",
]


#
# Tests
#
class EosAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(EosAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(EosAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(EosAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            EosAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(EosAddr is EosAddrEncoder)
