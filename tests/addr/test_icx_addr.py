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
from bip_utils import IcxAddr, IcxAddrDecoder, IcxAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"025bdd79558ff15825ba97e3f204789b109d8e096edd2dae7fbba1256a1b36a24a",
        "address_dec": b"477ac35d999d2db17b3a00cfcff70ea507f009ef",
        "address_params": {},
        "address": "hx477ac35d999d2db17b3a00cfcff70ea507f009ef",
    },
    {
        "pub_key": b"0262b58a61001654e430d83e8ad7abc1ce00723065fdbd9e417bfafe0207ffe317",
        "address_dec": b"1a986a81e2f8a93b5db9981694472ecbce25c23e",
        "address_params": {},
        "address": "hx1a986a81e2f8a93b5db9981694472ecbce25c23e",
    },
    {
        "pub_key": b"02e5b420f8f11d5dade44f26876e017401183271242fbce74c426d2b00d11ec53c",
        "address_dec": b"92081ffa16548def4b661df39becbbc80b59b061",
        "address_params": {},
        "address": "hx92081ffa16548def4b661df39becbbc80b59b061",
    },
    {
        "pub_key": b"03bfcf98524b0a9c0f41a416913f8a6c59a758580331996b21c5905845559e48bc",
        "address_dec": b"7f8d9c05cab379b0403eb8cfa20963ce8a23343a",
        "address_params": {},
        "address": "hx7f8d9c05cab379b0403eb8cfa20963ce8a23343a",
    },
    {
        "pub_key": b"02139ccffaaf29fdc6725cd53e443a910e948abb015bfd14ff87b513e62ef08056",
        "address_dec": b"000107cfddf025dcc4a098f8ddceec0cceb8b720",
        "address_params": {},
        "address": "hx000107cfddf025dcc4a098f8ddceec0cceb8b720",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid prefix
    "ix000107cfddf025dcc4a098f8ddceec0cceb8b720",
    # Invalid lengths
    "hx000107cfddf025dcc4a098f8ddceec0cceb8b7",
    "hx000107cfddf025dcc4a098f8ddceec0cceb8b72000",
]


#
# Tests
#
class IcxAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(IcxAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(IcxAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(IcxAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            IcxAddrEncoder,
            {},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(IcxAddr is IcxAddrEncoder)
