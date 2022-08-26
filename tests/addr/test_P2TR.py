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
from bip_utils import CoinsConf, P2TRAddr, P2TRAddrDecoder, P2TRAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    #
    # Main nets
    #
    {
        "pub_key": b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "address_dec": b"2771c09790b183d19c4a848282a37cb18b6aaf7edd863a689713bc7254ece2b7",
        "address_params": {
            "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp"),
        },
        "address": "bc1pyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msq4xugp",
    },
    {
        "pub_key": b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
        "address_dec": b"80d015c9d3154474036b7a5b5459387d70cbb49343495276b1d322235c612b77",
        "address_params": {
            "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp"),
        },
        "address": "bc1psrgptjwnz4z8gqmt0fd4gkfc04cvhdyngdy4ya436v3zxhrp9dmsd05jqz",
    },
    #
    # Test nets
    #
    {
        "pub_key": b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
        "address_dec": b"0449445395669a6af387056764a5a5c41d68c5fe9cdaca6d11fe85352f331014",
        "address_params": {
            "hrp": CoinsConf.BitcoinTestNet.ParamByKey("p2tr_hrp"),
        },
        "address": "tb1pq3y5g5u4v6dx4uu8q4nkffd9cswk3307nndv5mg3l6zn2tenzq2qufyzlx",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "ac1pyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msrd3lm7",
    # Invalid witness version
    "bc1zyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msgglnx2",
    # No separator
    "bcpyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msq4xugp",
    # Invalid checksum
    "bc1pyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msjsmz2a",
    # Invalid encoding
    "bc1pyacup9uskxpbr8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2msq4xugp",
    # Invalid lengths
    "bc1pw8qf0y93s0gecj5ys2p2xl933d427lkascax39cnh3e9fm8zkude9hqn",
    "bc1pyacup9uskxpar8z2sjpg9gmukx9k4tm7mkrr56yhzw78y48vu2m555np8lf",
]


#
# Tests
#
class P2TRTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(P2TRAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(P2TRAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            P2TRAddrDecoder,
            {
                "hrp": CoinsConf.BitcoinMainNet.ParamByKey("p2tr_hrp"),
            },
            TEST_VECT_DEC_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            P2TRAddrEncoder,
            {"hrp": ""},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(P2TRAddr is P2TRAddrEncoder)
