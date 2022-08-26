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
from bip_utils import OkexAddr, OkexAddrDecoder, OkexAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"03baf0b46095920af1a8c636cd9d9df37286190607d44ed82688f62c6c002acbc8",
        "address_dec": b"ac423557b17effaaec48ffaa9b93971b907513cc",
        "address_params": {},
        "address": "ex143pr24a30ml64mzgl74fhyuhrwg82y7vmyse7q",
    },
    {
        "pub_key": b"027bba228d456609587ce5d30f63443f421a3b187f6c53c53ba7626568a1025081",
        "address_dec": b"ba6f451ef1af60d583cb8dbdfbc196b831155f04",
        "address_params": {},
        "address": "ex1hfh528h34asdtq7t3k7lhsvkhqc32hcypk3gyt",
    },
    {
        "pub_key": b"03ec14157c1bb62c6b8ce10b7379bee621a6f79735b950eaf125913a3da19bdaf9",
        "address_dec": b"f3edea598195783440a79cff6bdd222be43e7d36",
        "address_params": {},
        "address": "ex170k75kvpj4urgs98nnlkhhfz90jrulfkq5k8rn",
    },
    {
        "pub_key": b"03b5f6bafd1656dbd1502b7d941d7bed5cfb2d1b479be9506e92752c96c5145965",
        "address_dec": b"74ab3ba156a57b91c08c90d1661650ac01eaafb2",
        "address_params": {},
        "address": "ex1wj4nhg2k54aersyvjrgkv9js4sq74tajsg6zm0",
    },
    {
        "pub_key": b"03068feb64a09aee06eac40abfabd16574e78108948405cc566f175509e17ebb52",
        "address_dec": b"edb51652893e7daa08168f31368c4c5a8b26c963",
        "address_params": {},
        "address": "ex1ak63v55f8e765zqk3ucndrzvt29jdjtrkz33f2",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "ix1wj4nhg2k54aersyvjrgkv9js4sq74taj2hxsth",
    # No separator
    "ex43pr24a30ml64mzgl74fhyuhrwg82y7vmyse7q",
    # Invalid checksum
    "ex13ml09c5zxqgtn0quzgwn8xvx79qe5p4xc3g2ws",
    # Invalid encoding
    "ex143pr24b30ml64mzgl74fhyuhrwg82y7vmyse7q",
    # Invalid lengths
    "ex1lmew9q3szzumc8qjr5eenph3gxdqdfsj63p9a",
    "one13ml09c5zxqgtn0quzgwn8xvx79qe5p4xsxjhyn",
]


#
# Tests
#
class OkexAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(OkexAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(OkexAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(OkexAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            OkexAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(OkexAddr is OkexAddrEncoder)
