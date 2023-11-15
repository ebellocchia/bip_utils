# Copyright (c) 2023 Emanuele Bellocchia
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

import unittest

# Imports
from typing import Any

from bip_utils import Blake2b256, Brainwallet, BrainwalletAlgos, BrainwalletCoins, IBrainwalletAlgo, Kekkak256


# Class for custom algorithm 1
class BrainwalletCustomAlgo1(IBrainwalletAlgo):
    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        return Kekkak256.QuickDigest(passphrase)


# Class for custom algorithm 2
class BrainwalletCustomAlgo2(IBrainwalletAlgo):
    @staticmethod
    def ComputePrivateKey(passphrase: str,
                          **kwargs: Any) -> bytes:
        return Blake2b256.QuickDigest(passphrase, salt=kwargs["salt"])


# Test vector (built-in algorithms)
TEST_VECT_BUILT_IN_ALGO = [
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.BITCOIN,
        "algo_type": BrainwalletAlgos.SHA256,
        "algo_params": {},
        "priv_key": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "address": "13SiBXw8v8NVJPx8vjss1S71kFQFaYD5fW",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.BITCOIN,
        "algo_type": BrainwalletAlgos.DOUBLE_SHA256,
        "algo_params": {},
        "priv_key": "6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937",
        "address": "1927YyaRnrPgwN8zTzWSajApN5QPrmAJuk",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.BITCOIN,
        "algo_type": BrainwalletAlgos.PBKDF2_HMAC_SHA512,
        "algo_params": {
            "salt": "Custom salt",
        },
        "priv_key": "94b7ff6451bd57b3fe550ca19ed899501f349373d0ad6b833ee11978c4cd332d",
        "address": "14oQH5iepDVFBwokqQHxojEWzb7dqNFtV3",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.LITECOIN,
        "algo_type": BrainwalletAlgos.PBKDF2_HMAC_SHA512,
        "algo_params": {
            "salt": "Custom salt",
            "itr_num": 1024 * 1024,
        },
        "priv_key": "cc01c564bbd1d9bd2c1fc3f20e598a0664ec22f5c42957085b76800ef6ae3b6d",
        "address": "Le5vZveQCdw6QwbHCZjwUHkQU5ZNEHcEH2",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.ETHEREUM,
        "algo_type": BrainwalletAlgos.SCRYPT,
        "algo_params": {
            "salt": "Custom salt",
        },
        "priv_key": "8df7c5e5aa5c9a8dca96d06ea8971a1a1b5d15a70e13db6b22928278694330ee",
        "address": "0x3C628F056C2C9240B95330B88aaff2B5B6740c5D",
    },
]

# Test vector (custom algorithm)
TEST_VECT_CUSTOM_ALGO = [
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.BITCOIN,
        "algo_cls": BrainwalletCustomAlgo1,
        "algo_params": {},
        "priv_key": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        "address": "1DRgLt399wpHfhoDEgLTLtSmpSvzKVtkcw",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.LITECOIN,
        "algo_cls": BrainwalletCustomAlgo1,
        "algo_params": {},
        "priv_key": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        "address": "LXedc6LyEc4LvWVNQpKkcuWY2fJGUMgt6p",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.BITCOIN,
        "algo_cls": BrainwalletCustomAlgo2,
        "algo_params": {
            "salt": "Custom salt",
        },
        "priv_key": "9ceaa5248f58a380f23795affabb0b24967198a337b2fa8f8c781e5c6cc635b8",
        "address": "1QAGdY7fNxnro7AJXzBfw2hew7FfR3jK1",
    },
    {
        "passphrase": "The quick brown fox jumps over the lazy dog",
        "coin_type": BrainwalletCoins.ETHEREUM,
        "algo_cls": BrainwalletCustomAlgo2,
        "algo_params": {
            "salt": "Custom salt",
        },
        "priv_key": "9ceaa5248f58a380f23795affabb0b24967198a337b2fa8f8c781e5c6cc635b8",
        "address": "0xF513cAb3642cE3214017D4268Fcf78eEeA9AbE7d",
    },
]


#
# Tests
#
class BrainwalletTests(unittest.TestCase):
    # Test (built-in algorithms)
    def test_built_in_algo(self):
        for test in TEST_VECT_BUILT_IN_ALGO:
            brainwallet = Brainwallet.Generate(
                test["passphrase"],
                test["coin_type"],
                test["algo_type"],
                **test["algo_params"],
            )
            self.assertEqual(test["priv_key"], brainwallet.PrivateKey().Raw().ToHex())
            self.assertEqual(test["address"], brainwallet.PublicKey().ToAddress())

    # Test (custom algorithm)
    def test_custom_algo(self):
        for test in TEST_VECT_CUSTOM_ALGO:
            brainwallet = Brainwallet.GenerateWithCustomAlgo(
                test["passphrase"],
                test["coin_type"],
                test["algo_cls"],
                **test["algo_params"],
            )
            self.assertEqual(test["priv_key"], brainwallet.PrivateKey().Raw().ToHex())
            self.assertEqual(test["address"], brainwallet.PublicKey().ToAddress())

    # Test invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError,
                          Brainwallet.Generate,
                          "test",
                          0,
                          BrainwalletAlgos.SHA256)
        self.assertRaises(TypeError,
                          Brainwallet.Generate,
                          "test",
                          BrainwalletCoins.BITCOIN,
                          0)
