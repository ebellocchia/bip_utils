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
from bip_utils import AtomAddr, AtomAddrDecoder, AtomAddrEncoder, CoinsConf
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_SECP256K1_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_SECP256K1_PUB_KEY_INVALID, Secp256k1PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"039cb22e5c6ce15e06b76d5725dcf084b87357d926dcdfeeb20d628d3d11ff543b",
        "address_dec": b"165c9dab1586b8ca42a323ad0037333b584ed5db",
        "address_params": {"hrp": CoinsConf.Cosmos.ParamByKey("addr_hrp")},
        "address": "cosmos1zewfm2c4s6uv5s4rywksqden8dvya4wmqyyvek",
    },
    {
        "pub_key": b"02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "address_dec": b"9eb88dffa323736f58ee87c5c25290ca569cf90a",
        "address_params": {"hrp": CoinsConf.Cosmos.ParamByKey("addr_hrp")},
        "address": "cosmos1n6ugmlarydek7k8wslzuy55seftfe7g2aqncw3",
    },
    {
        "pub_key": b"0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "address_dec": b"d4f22d7dab7883aa9c48b1d0aea68f55684792d2",
        "address_params": {"hrp": CoinsConf.BandProtocol.ParamByKey("addr_hrp")},
        "address": "band16nez6ldt0zp648zgk8g2af50245y0ykjutc2k9",
    },
    {
        "pub_key": b"02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "address_dec": b"d762167cf2da4f5e3079cdbc5dafb490cfffef13",
        "address_params": {"hrp": CoinsConf.BandProtocol.ParamByKey("addr_hrp")},
        "address": "band16a3pvl8jmf84uvreek79mta5jr8llmcn4ptgy2",
    },
    {
        "pub_key": b"0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "address_dec": b"d4f22d7dab7883aa9c48b1d0aea68f55684792d2",
        "address_params": {"hrp": CoinsConf.Kava.ParamByKey("addr_hrp")},
        "address": "kava16nez6ldt0zp648zgk8g2af50245y0ykje3v4c2",
    },
    {
        "pub_key": b"02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "address_dec": b"d762167cf2da4f5e3079cdbc5dafb490cfffef13",
        "address_params": {"hrp": CoinsConf.Kava.ParamByKey("addr_hrp")},
        "address": "kava16a3pvl8jmf84uvreek79mta5jr8llmcnsmlh29",
    },
    {
        "pub_key": b"02ec5dc71723f11e8ed7ae054f1c09110e849edfa491118d161473b78d72cc4813",
        "address_dec": b"e191b92395ce7fa4ed5f99ce8cc744792a22bf0a",
        "address_params": {"hrp": CoinsConf.IrisNet.ParamByKey("addr_hrp")},
        "address": "iaa1uxgmjgu4eel6fm2ln88ge36y0y4z90c2knr3d6",
    },
    {
        "pub_key": b"02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "address_dec": b"9eb88dffa323736f58ee87c5c25290ca569cf90a",
        "address_params": {"hrp": CoinsConf.IrisNet.ParamByKey("addr_hrp")},
        "address": "iaa1n6ugmlarydek7k8wslzuy55seftfe7g2gznfvq",
    },
    {
        "pub_key": b"03de159b5635abfdb91b6ae3bf57317d3ecc4eb7a734ef72cc18f307e83359b854",
        "address_dec": b"5811db8a383d0d589d88cde9e16a2383eb885ff8",
        "address_params": {"hrp": CoinsConf.Terra.ParamByKey("addr_hrp")},
        "address": "terra1tqgahz3c85x438vgeh57z63rs04cshlcx5ga4z",
    },
    {
        "pub_key": b"033e444813a45a334240087619ffc73e626db10454738e08dbdfc71741fb44af26",
        "address_dec": b"32db6a56c4fb538b3e92c95bdcca87c9fdcc99e2",
        "address_params": {"hrp": CoinsConf.Terra.ParamByKey("addr_hrp")},
        "address": "terra1xtdk54kyldfck05je9daej58e87uex0zk47rz5",
    },
    {
        "pub_key": b"0223d645338396fdbce2d754a14568537d52deb76e1addb940994868feef9c5994",
        "address_dec": b"fba4d69d5c95520bf0f303a8d2d0a3b92143b718",
        "address_params": {"hrp": CoinsConf.BinanceChain.ParamByKey("addr_hrp")},
        "address": "bnb1lwjdd82uj4fqhu8nqw5d959rhys58dccv9aalj",
    },
    {
        "pub_key": b"03ebbc8a33683fa9d40f4da3b870784d7f66911eec4d464993c2b80d891d452f93",
        "address_dec": b"d5beb4d04fb2371df8d555e3af68d9bac3f7ab10",
        "address_params": {"hrp": CoinsConf.BinanceChain.ParamByKey("addr_hrp")},
        "address": "bnb16kltf5z0kgm3m7x42h3676xehtpl02csg7f3qc",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid HRP
    "cosmis1pgmhz30d29akc670hkaje398hl6hvh0c5w0gly",
    # No separator
    "cosmoszewfm2c4s6uv5s4rywksqden8dvya4wmqyyvek",
    # Invalid checksum
    "cosmos19c3mc3hp8y624tae0mfnmxse9h49kv2pqltkj0",
    # Invalid encoding
    "cosmos1lwjdb82uj4fqhu8nqw5d959rhys58dccwpz37u",
    # Invalid lengths
    "cosmos15ntf6hy42g9lpucr4rfdpgaey9pmwxq3al8gd",
    "cosmos1zx807pf53fgwnhnu6du3xvsqk6yruz7adepaaz6q0szyp57m63hqpwdtkp",
]


#
# Tests
#
class AtomAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(AtomAddrEncoder, Secp256k1PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(AtomAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(AtomAddrDecoder, {"hrp": "cosmos"}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            AtomAddrEncoder,
            {"hrp": ""},
            TEST_SECP256K1_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_SECP256K1_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AtomAddr is AtomAddrEncoder)
