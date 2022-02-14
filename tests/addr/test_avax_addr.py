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
import unittest
from bip_utils import AvaxPChainAddr, AvaxXChainAddr
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey

# Some random public keys
TEST_VECT = {
    "x_chain": [
        {
            "pub_key": b"02add530ea489143b936d2430e8412182984cdb26c020ce18ddc34dbf24a442b7d",
            "dec_addr": b"54517930c6a96e7f21ecb2b582fb1d39a2cad514",
            "addr_params": {},
            "address": "X-avax123ghjvxx49h87g0vk26c97ca8x3v44g5n9mzha",
        },
        {
            "pub_key": b"03465789245ff8a454efc9a72608521f30bcc49e35f1bf26272d0a6cb7a7b91876",
            "dec_addr": b"d56df34d4a10d48a82bb8d9f1110f0b0c281ae3a",
            "addr_params": {},
            "address": "X-avax164klxn22zr2g4q4m3k03zy8skrpgrt36sqm5r4",
        },
    ],
    "p_chain": [
        {
            "pub_key": b"03a90de501b386356e40d9800431f06698241414590498903b80f0aeb184dfa537",
            "dec_addr": b"a82bc437faa43a891abd829e9e0131f671dcf5b8",
            "addr_params": {},
            "address": "P-avax14q4ugdl65sagjx4as20fuqf37ecaeadcqm96zt",
        },
        {
            "pub_key": b"0317e4b698b4e370ced9fec7c02bfd5c56055e07db49fdc623b1545eb7a61a1287",
            "dec_addr": b"cd5d0bda4c00538e70faee3fa29bad3c3fe14108",
            "addr_params": {},
            "address": "P-avax1e4wshkjvqpfcuu86acl69xad8sl7zsgg723xu3",
        },
    ],
}

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "A-avax1e4wshkjvqpfcuu86acl69xad8sl7zsgg723xu3",
]


#
# Tests
#
class AvaxAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, AvaxPChainAddr, Secp256k1PublicKey, TEST_VECT["p_chain"])
        AddrBaseTestHelper.test_encode_key(self, AvaxXChainAddr, Secp256k1PublicKey, TEST_VECT["x_chain"])

    # Test decode addr
    def test_decode_addr(self):
        AddrBaseTestHelper.test_decode_addr(self, AvaxPChainAddr, TEST_VECT["p_chain"])
        AddrBaseTestHelper.test_decode_addr(self, AvaxXChainAddr, TEST_VECT["x_chain"])

    # Test invalid decoding
    def test_invalid_dec(self):
        AddrBaseTestHelper.test_invalid_dec(self, AvaxPChainAddr, {}, TEST_VECT_DEC_INVALID)
        AddrBaseTestHelper.test_invalid_dec(self, AvaxXChainAddr, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             AvaxPChainAddr,
                                             {},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
        AddrBaseTestHelper.test_invalid_keys(self,
                                             AvaxXChainAddr,
                                             {},
                                             TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_SECP256K1_PUB_KEY_INVALID)
