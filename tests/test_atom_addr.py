# Copyright (c) 2020 Emanuele Bellocchia
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
import unittest
from bip_utils import AtomAddr, Secp256k1

# Some keys randomly taken (verified with Cosmostation wallet)
TEST_VECT = [
    {
        "pub_key": b"039cb22e5c6ce15e06b76d5725dcf084b87357d926dcdfeeb20d628d3d11ff543b",
        "hrp": "cosmos",
        "address": "cosmos1zewfm2c4s6uv5s4rywksqden8dvya4wmqyyvek",
    },
    {
        "pub_key": b"02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "hrp": "cosmos",
        "address": "cosmos1n6ugmlarydek7k8wslzuy55seftfe7g2aqncw3",
    },
    {
        "pub_key": b"0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "hrp": "band",
        "address": "band16nez6ldt0zp648zgk8g2af50245y0ykjutc2k9",
    },
    {
        "pub_key": b"02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "hrp": "band",
        "address": "band16a3pvl8jmf84uvreek79mta5jr8llmcn4ptgy2",
    },
    {
        "pub_key": b"0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "hrp": "kava",
        "address": "kava16nez6ldt0zp648zgk8g2af50245y0ykje3v4c2",
    },
    {
        "pub_key": b"02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "hrp": "kava",
        "address": "kava16a3pvl8jmf84uvreek79mta5jr8llmcnsmlh29",
    },
    {
        "pub_key": b"02ec5dc71723f11e8ed7ae054f1c09110e849edfa491118d161473b78d72cc4813",
        "hrp": "iaa",
        "address": "iaa1uxgmjgu4eel6fm2ln88ge36y0y4z90c2knr3d6",
    },
    {
        "pub_key": b"02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "hrp": "iaa",
        "address": "iaa1n6ugmlarydek7k8wslzuy55seftfe7g2gznfvq",
    },
    {
        "pub_key": b"03de159b5635abfdb91b6ae3bf57317d3ecc4eb7a734ef72cc18f307e83359b854",
        "hrp": "terra",
        "address": "terra1tqgahz3c85x438vgeh57z63rs04cshlcx5ga4z",
    },
    {
        "pub_key": b"033e444813a45a334240087619ffc73e626db10454738e08dbdfc71741fb44af26",
        "hrp": "terra",
        "address": "terra1xtdk54kyldfck05je9daej58e87uex0zk47rz5",
    },
    {
        "pub_key": b"0223d645338396fdbce2d754a14568537d52deb76e1addb940994868feef9c5994",
        "hrp": "bnb",
        "address": "bnb1lwjdd82uj4fqhu8nqw5d959rhys58dccv9aalj",
    },
    {
        "pub_key": b"03ebbc8a33683fa9d40f4da3b870784d7f66911eec4d464993c2b80d891d452f93",
        "hrp": "bnb",
        "address": "bnb16kltf5z0kgm3m7x42h3676xehtpl02csg7f3qc",
    },
]

# Tests for invalid keys
TEST_VECT_KEY_INVALID = [
    # Private key
    b"132750b8489385430d8bfa3871ade97da7f5d5ef134a5c85184f88743b526e38",
    # Compressed public key with valid length but wrong version
    b"019efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c70",
    # Compressed public key with invalid length
    b"029efbcb2db9ee44cb12739e9350e19e5f1ce4563351b770096f0e408f93400c7000",
    # Uncompressed public key with valid length but wrong version
    b"058ccab10df42f89efaf13ca23a96f8b2063d881601c195b354f6f49c3b5978dd4e17e3a1b1505fcb5e7d13b042fa5c8eff83c1efe17d8a56e3cf3fa9250cb80fe",
    # Uncompressed public key with invalid length
    b"04fd87569e9af6015d9d938c67c68fcdf5440d3c235eccbc1195a1924bba90e5e1954cb6d841054791ac227a8c11f79f77d24a20b238402c5424c8e436bb49",
]


#
# Tests
#
class AtomAddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_to_addr(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], AtomAddr.ToAddress(key_bytes, test["hrp"]))
            self.assertEqual(test["address"], AtomAddr.ToAddress(Secp256k1.PublicKeyFromBytes(key_bytes), test["hrp"]))

    # Test invalid keys
    def test_invalid_keys(self):
        for test in TEST_VECT_KEY_INVALID:
            self.assertRaises(ValueError, AtomAddr.ToAddress, binascii.unhexlify(test), "cosmos")
