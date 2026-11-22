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
from bip_utils import CoinsConf, KasAddr, KasAddrDecoder, KasAddrEncoder, KasAddrTypes
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Public keys derived from the master key of rusty-kaspa tests, the addresses are the ones of rusty-kaspa tests:
# https://github.com/kaspanet/rusty-kaspa/blob/master/wallet/keys/src/derivation/gen1/hd.rs
# https://github.com/kaspanet/rusty-kaspa/blob/master/crypto/addresses/src/lib.rs
TEST_VECT = [
    #
    # Main net
    #
    {
        "pub_key": b"02bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_dec": b"bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_params": {
            "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
        },
        "address": "kaspa:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjellj43pf",
    },
    {
        "pub_key": b"03a710484954c446c4528be33b560863fbdcd54c8f13c5da8681b164e7f0a79a69",
        "address_dec": b"a710484954c446c4528be33b560863fbdcd54c8f13c5da8681b164e7f0a79a69",
        "address_params": {
            "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY,
        },
        "address": "kaspa:qzn3qjzf2nzyd3zj303nk4sgv0aae42v3ufutk5xsxckfels57dxjjed4qvlx",
    },
    {
        "pub_key": b"03c039904d75cb9c280fa23822458c8c527d4d8d23a8a03bfbb3f79708d16a1b08",
        "address_dec": b"c039904d75cb9c280fa23822458c8c527d4d8d23a8a03bfbb3f79708d16a1b08",
        "address_params": {
            "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY,
        },
        "address": "kaspa:qrqrnyzdwh9ec2q05guzy3vv33f86nvdyw52qwlmk0mewzx3dgdss3pmcd692",
    },
    {
        "pub_key": b"025fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522",
        "address_dec": b"5fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522",
        "address_params": {
            "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY,
        },
        "address": "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj",
    },
    {
        "pub_key": b"02bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_dec": b"02bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_params": {
            "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY_ECDSA,
        },
        "address": "kaspa:qyptmnljhp23kleyt8q52gs0077wcgdz4mdyu5reqgw9pywz28stg6gs8y7nplv",
    },
    #
    # Test net
    #
    {
        "pub_key": b"02bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_dec": b"bdcff2b8551b7f2459c145220f7fbcec21a2aeda4e5079021c5091c251e0b469",
        "address_params": {
            "hrp": CoinsConf.KaspaTestNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY,
        },
        "address": "kaspatest:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjceef60sd",
    },
    {
        "pub_key": b"03a710484954c446c4528be33b560863fbdcd54c8f13c5da8681b164e7f0a79a69",
        "address_dec": b"a710484954c446c4528be33b560863fbdcd54c8f13c5da8681b164e7f0a79a69",
        "address_params": {
            "hrp": CoinsConf.KaspaTestNet.ParamByKey("addr_hrp"),
            "addr_type": KasAddrTypes.PUB_KEY,
        },
        "address": "kaspatest:qzn3qjzf2nzyd3zj303nk4sgv0aae42v3ufutk5xsxckfels57dxjnltw0jwz",
    },
]

# Tests for decoding with invalid strings (public key type)
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "kaspb:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xj35zs0dyd",
    # Invalid address type
    "kaspa:qx7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xj0qrqsfsq",
    # No separator
    "kaspaqz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjellj43pf",
    # Invalid checksum
    "kaspa:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjellj43pq",
    # Invalid encoding
    "kaspa:qz7ubu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjellj43pf",
    # Invalid public key
    "kaspa:qq6rlkdrq4pd0xqsdhsutf3dgspu3tmusshprwku27xjr64u7j66vharx5zdl",
    # Invalid lengths
    "kaspa:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6qtxrmugcn",
    "kaspa:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjqqyutsg2qm",
]

# Tests for decoding with invalid strings (ECDSA public key type)
TEST_VECT_DEC_INVALID_ECDSA = [
    # Invalid address type
    "kaspa:qqptmnljhp23kleyt8q52gs0077wcgdz4mdyu5reqgw9pywz28stg6g8phpqd3p",
    # Invalid public key
    "kaspa:qyprg07e5vz594uczpk7r3dx94zq8j900jzzuyd6m3tc6g02hn6ttfsz3w3hrsw",
    # Invalid lengths
    "kaspa:qyptmnljhp23kleyt8q52gs0077wcgdz4mdyu5reqgw9pywz28stga8pdd8t4",
    "kaspa:qyptmnljhp23kleyt8q52gs0077wcgdz4mdyu5reqgw9pywz28stg6gqyae8xxw3",
]

# Valid address from rusty-kaspa tests, but containing an invalid ECDSA public key
TEST_VECT_DEC_INVALID_ECDSA_TESTNET = [
    "kaspatest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrse6gdmpks",
]


#
# Tests
#
class KasAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(KasAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(KasAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            KasAddrDecoder,
            {
                "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
                "addr_type": KasAddrTypes.PUB_KEY,
            },
            TEST_VECT_DEC_INVALID
        )
        self._test_invalid_dec(
            KasAddrDecoder,
            {
                "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
                "addr_type": KasAddrTypes.PUB_KEY_ECDSA,
            },
            TEST_VECT_DEC_INVALID_ECDSA
        )
        self._test_invalid_dec(
            KasAddrDecoder,
            {
                "hrp": CoinsConf.KaspaTestNet.ParamByKey("addr_hrp"),
                "addr_type": KasAddrTypes.PUB_KEY_ECDSA,
            },
            TEST_VECT_DEC_INVALID_ECDSA_TESTNET
        )

    # Test invalid keys
    def test_invalid_keys(self):
        for addr_type in KasAddrTypes:
            self._test_invalid_keys(
                KasAddrEncoder,
                {
                    "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
                    "addr_type": addr_type,
                },
                TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
                TEST_VECT_SECP256K1_PUB_KEY_INVALID
            )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            KasAddrDecoder,
            {
                "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
                "addr_type": 0,
            },
            TypeError
        )
        self._test_invalid_params_enc(
            KasAddrEncoder,
            {
                "hrp": CoinsConf.KaspaMainNet.ParamByKey("addr_hrp"),
                "addr_type": 0,
            },
            TypeError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(KasAddr is KasAddrEncoder)
