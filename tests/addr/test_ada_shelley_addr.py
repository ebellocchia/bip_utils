# Copyright (c) 2022 Emanuele Bellocchia
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

from bip_utils import (
    AdaShelleyAddr, AdaShelleyAddrDecoder, AdaShelleyAddrEncoder, AdaShelleyAddrNetworkTags, AdaShelleyRewardAddr,
    AdaShelleyRewardAddrDecoder, AdaShelleyRewardAddrEncoder, AdaShelleyStakingAddr, AdaShelleyStakingAddrDecoder,
    AdaShelleyStakingAddrEncoder
)
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_ED25519_PUB_KEY, TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519KholawPublicKey


# Some random public keys for addresses
TEST_VECT_ADDRESS = [
    {
        "pub_key": b"01f9256746c79ad5ba163ae677e3e3477471f0c3f8e1b5012c7a09f862e3972d",
        "address_dec": b"0ea494eb8231e7070bd0d697af52425e043e0a9c07b0125e01dcd24c62e860f974ebe501d47cdfa05184f9eb190e3cf7f00f0e58d5fbdc6e",
        "address_params": {
            "pub_skey": binascii.unhexlify(b"7680c767b8096daa3299dc282068327c79976f346e55b72d0ffd751295a45913"),
        },
        "address": "addr1qy82f98tsgc7wpct6rtf0t6jgf0qg0s2nsrmqyj7q8wdynrzaps0ja8tu5qaglxl5pgcf70try8realspu89340mm3hq6jjmds",
    },
    {
        "pub_key": b"536f21ca63366435d1172c904881f4ab522599ffbd0312c14cd812e2763b37eb",
        "address_dec": b"36ba392f729a3264bfe7d573f22f4d04c498456c027bac97ac7f6f87cfff9ed681cc4500ec33e764b04a9aaa6f6fc7d0be70c5f5bb05e9a0",
        "address_params": {
            "pub_skey": binascii.unhexlify(b"4a3869ac2c55b83898016041817e47c67d89214f60f78ba8d4591f1545271dc1"),
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "addr1qymt5wf0w2drye9lul2h8u30f5zvfxz9dsp8htyh43lklp70l70ddqwvg5qwcvl8vjcy4x42dahu0597wrzltwc9axsqx5l9wh",
    },
    {
        "pub_key": b"6e6c430ee031e831280795e42401dd45a53c7059323156a51659991d1c3a25c7",
        "address_dec": b"bfae29ef2ee21e52354d25b63c833601effef20a28416db030f406eb4cdbcb0cac56366d6195808f9ea9a5d17c5a3b184ff685cc7d84b363",
        "address_params": {
            "pub_skey": binascii.unhexlify(b"e0a4e859cbe847c4877e5203559fe997e22c6b700362af6767bf3d9c3b9343c7"),
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "addr1qxl6u2009m3pu534f5jmv0yrxcq7llhjpg5yzmdsxr6qd66vm09setzkxekkr9vq3702nfw303drkxz076zuclvykd3sejrk53",
    },
    {
        "pub_key": b"0dc6fecd828828750cf2627d2078561994477d8fe08240a593f979c2a52e5dea",
        "address_dec": b"e8ed2050d5ee6b751d57007820c3778a21e649b10a1fe148985d8249d3990dee560b4915dc3720e9a71e8931b47ed28eb2da91fcc2b9c14d",
        "address_params": {
            "pub_skey": binascii.unhexlify(b"6b72d1d7ce598245734a6f92093b477298f47626ac1a446bc65f48d420a7eed6"),
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "addr1q85w6gzs6hhxkaga2uq8sgxrw79zrejfky9plc2gnpwcyjwnnyx7u4stfy2acdeqaxn3azf3k3ld9r4jm2gles4ec9xstvp7vy",
    },
    {
        "pub_key": b"3bac00235a132984c939cdbb1e65bdd8421a59b5e98ebb46dc35bc7dd58f5d1e",
        "address_dec": b"785d2ac12adb2afdf2c046fed50c7c1bb474b74b0307b740551a1b6103bf8d55c7ff570dd4eb783f49ffa5987b2734cdc85557289ef64235",
        "address_params": {
            "pub_skey": binascii.unhexlify(b"fa9e3a2bfdbcb0eec7af89313b504418da860728c7ec9ed7d939d1e9e2b683c0"),
            "net_tag": AdaShelleyAddrNetworkTags.TESTNET,
        },
        "address": "addr_test1qpu962kp9tdj4l0jcpr0a4gv0sdmga9hfvps0d6q25dpkcgrh7x4t3ll2uxaf6mc8ayllfvc0vnnfnwg24tj38hkgg6s2x67qn",
    },
]

# Some random public keys for reward addresses
TEST_VECT_REWARD_ADDRESS = [
    {
        "pub_key": b"7680c767b8096daa3299dc282068327c79976f346e55b72d0ffd751295a45913",
        "address_dec": b"62e860f974ebe501d47cdfa05184f9eb190e3cf7f00f0e58d5fbdc6e",
        "address_params": {},
        "address": "stake1u93wsc8ewn472qw50n06q5vyl843jr3u7lcq7rjc6haacmsfwqcqn",
    },
    {
        "pub_key": b"4a3869ac2c55b83898016041817e47c67d89214f60f78ba8d4591f1545271dc1",
        "address_dec": b"cfff9ed681cc4500ec33e764b04a9aaa6f6fc7d0be70c5f5bb05e9a0",
        "address_params": {
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "stake1u88ll8kks8xy2q8vx0nkfvz2n24x7m786zl8p304hvz7ngqcx6xaz",
    },
    {
        "pub_key": b"e0a4e859cbe847c4877e5203559fe997e22c6b700362af6767bf3d9c3b9343c7",
        "address_dec": b"4cdbcb0cac56366d6195808f9ea9a5d17c5a3b184ff685cc7d84b363",
        "address_params": {
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "stake1u9xdhjcv43trvmtpjkqgl84f5hghck3mrp8ldpwv0kztxccc8t6wz",
    },
    {
        "pub_key": b"6b72d1d7ce598245734a6f92093b477298f47626ac1a446bc65f48d420a7eed6",
        "address_dec": b"d3990dee560b4915dc3720e9a71e8931b47ed28eb2da91fcc2b9c14d",
        "address_params": {
            "net_tag": AdaShelleyAddrNetworkTags.MAINNET,
        },
        "address": "stake1u8fejr0w2c95j9wuxuswnfc73ycmglkj36ed4y0uc2uuzng0rx39x",
    },
    {
        "pub_key": b"fa9e3a2bfdbcb0eec7af89313b504418da860728c7ec9ed7d939d1e9e2b683c0",
        "address_dec": b"03bf8d55c7ff570dd4eb783f49ffa5987b2734cdc85557289ef64235",
        "address_params": {
            "net_tag": AdaShelleyAddrNetworkTags.TESTNET,
        },
        "address": "stake_test1uqpmlr24cll4wrw5adur7j0l5kv8kfe5ehy924egnmmyydgpa9wtr",
    },
]

# Tests for decoding with invalid strings for addresses
TEST_VECT_DEC_INVALID_ADDRESS = [
    # Invalid HRP
    "cddr1q8g92c5s6s7m7yqjldz2da5gkfh8dzml76wp5lhfm3wvlpqr7nw0ufmze0xak8r2j56z47q32hfvkamcylzxxvwgvamqpjgzne",
    # No separator
    "addrq9u962kp9tdj4l0jcpr0a4gv0sdmga9hfvps0d6q25dpkcgrh7x4t3ll2uxaf6mc8ayllfvc0vnnfnwg24tj38hkgg6sfs87vv",
    # Invalid checksum
    "addr1q9hamruwl3x78q8n6apv5xajjp4rnz40k8hadgw83lm2f7gglc6ae0xz4vr3mv2s67fau2ctn3qlgyre6d69ns5qyyxqujzuv3",
    # Invalid encoding
    "addr1q85w6gzs6hhxkagb2uq8sgxrw79zrejfky9plc2gnpwcyjwnnyx7u4stfy2acdeqaxn3azf3k3ld9r4jm2gles4ec9xstvp7vy",
    # Invalid header type
    "addr1uydcux8l4hr29en7hrer9xf22y2rj6ty7l4ee2ku47upknekelt65xtnqdzl88ksmnrsy3m02lxms38685672l8f6nysnmruwn",
    # Invalid network tag
    "addr1qrgy2x7fadda4ylqe9t0udkwa6ulwuhxuuuclf3sx79hh3nxt6vygfc53zr6vv3fj3f3y335pv34e98paxy5xu9ydmlsk8fgjk",
    # Invalid lengths
    "addr1qxna6qgtua0qe32f95ghc3ye0evlk8xf9fjxjuujxqv5awkjeh6n4l47z4ynrggjs33md2veatxydpymz726j5am3d9fw7",
    "addr1qyxk0wdpkpjfuqrzj72j5k3qd7yn0wvzw33jxdjxuehf4gu5g30cfhwdxlme2j43uwuc7mhkdq06xyh0cwtvlj3cvfh367gwpduu2",
]

# Tests for decoding with invalid strings for reward addresses
TEST_VECT_DEC_INVALID_REWARD_ADDRESS = [
    # Invalid HRP
    "atake1uyplfh87ya3vhnwmr34f2dp2lqg4t5ktwauz03rrx8yxwasdk57pc",
    # No separator
    "stakeuypmlr24cll4wrw5adur7j0l5kv8kfe5ehy924egnmmyydgxh0v07",
    # Invalid checksum
    "stake1uyy0udwuhnp2kpcak9gd0y779v9ecs05zpuaxazec2qzzrq406esg",
    # Invalid encoding
    "stake1u8fbjr0w2c95j9wuxuswnfc73ycmglkj36ed4y0uc2uuzng0rx39x",
    # Invalid header type
    "stake1qymvl4a2r9esx30nnmgde3czgah40ndcgnar6d090n5afjgyj0z9h",
    # Invalid network tag
    "stake1upn9axzyyu2g3paxxg5eg5cjgc6qkg6ujns7nz2rwzjxalcqtdjga",
    # Invalid lengths
    "stake1uxad9n048tltu92fxxs39prrk65en6kvg6zfk9u449fmkq0dqdl",
    "stake1u9z9lpxae5ml0922k83mnrmw7e5plgcjalpedn728p3x78tell6znu",
]


#
# Tests
#
class AdaShelleyAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(AdaShelleyAddrEncoder, Ed25519KholawPublicKey, TEST_VECT_ADDRESS)
        self._test_encode_key(AdaShelleyStakingAddrEncoder, Ed25519KholawPublicKey, TEST_VECT_REWARD_ADDRESS)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(AdaShelleyAddrDecoder, TEST_VECT_ADDRESS)
        self._test_decode_addr(AdaShelleyStakingAddrDecoder, TEST_VECT_REWARD_ADDRESS)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            AdaShelleyAddrDecoder,
            {
                "pub_skey": TEST_ED25519_PUB_KEY,
            },
            TEST_VECT_DEC_INVALID_ADDRESS
        )
        self._test_invalid_dec(
            AdaShelleyStakingAddrDecoder,
            {},
            TEST_VECT_DEC_INVALID_REWARD_ADDRESS
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            AdaShelleyAddrEncoder,
            {
                "pub_skey": TEST_ED25519_PUB_KEY,
            },
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )
        self._test_invalid_keys(
            AdaShelleyStakingAddrEncoder,
            {},
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            AdaShelleyAddrDecoder,
            {
                "net_tag": 0,
            },
            TypeError
        )
        self._test_invalid_params_enc(
            AdaShelleyAddrEncoder,
            {
                "pub_skey": TEST_ED25519_PUB_KEY,
                "net_tag": 0,
            },
            TypeError
        )

        self._test_invalid_params_dec(
            AdaShelleyStakingAddrDecoder,
            {
                "net_tag": 0,
            },
            TypeError
        )
        self._test_invalid_params_enc(
            AdaShelleyStakingAddrEncoder,
            {
                "net_tag": 0,
            },
            TypeError
        )

    # Test reward address class
    def test_staking_addr_cls(self):
        self.assertTrue(AdaShelleyRewardAddrDecoder is AdaShelleyStakingAddrDecoder)
        self.assertTrue(AdaShelleyRewardAddrEncoder is AdaShelleyStakingAddrEncoder)
        self.assertTrue(AdaShelleyRewardAddr is AdaShelleyStakingAddr)

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AdaShelleyAddr is AdaShelleyAddrEncoder)
        self.assertTrue(AdaShelleyRewardAddr is AdaShelleyRewardAddrEncoder)
        self.assertTrue(AdaShelleyStakingAddr is AdaShelleyStakingAddrEncoder)
