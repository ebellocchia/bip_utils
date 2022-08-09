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
import unittest

from bip_utils import (
    CoinsConf, ElectrumV1, Secp256k1PrivateKey, Secp256k1PublicKey, WifDecoder, WifEncoder, WifPubKeyModes
)
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyDataConst
from tests.ecc.test_ecc import TEST_ED25519_PRIV_KEY, TEST_ED25519_PUB_KEY


# Test vector (verified with Electrum wallet)
TEST_VECT = [
    {
        "seed": b"0bbe2537d7527f2d7376d4bb9de8ac42ca202dbae310471b88f2cbb0492e6e73",
        "master_pub_key": "042e767c36bd48f70bc34704cabd5bb1394f374227c330bb17ed6b22ca44b85582d2d88a00fcf8f0f00b2ee32f8623b7d23def43c8c0784846b98c2abaf742693b",
        "master_priv_key": "5HuTXx6TC56nonxHfw3DmM72CurZ22zh24azdCmz3gh3We2Ujvk",
        "addresses": [
            {
                "address": "1P5Ai2wW2x93onQW5ZSDfHhu5LTgBPNx7r",
                "priv_key": "5K9JkKyEJ7yoF5dyZBHHQHyXTUPirhxwDYSFn4RV25bN6pXfhLu",
            },
            {
                "address": "1dGnYwstcGq5fsEkSkV3jpgbfKQf2wgR1",
                "priv_key": "5Ja4ec5Sy2CqA4hRJFkbfJGa3wkhsYyH2ewBbJkXQoK4GtRqp94",
            },
            {
                "address": "1CcNXYJW7DEtqLECPQGoTr8mhZEC7X9i8X",
                "priv_key": "5KJMwfQEhKSL4Pa6zY3f44tRTXxsSBFBfGtdTe9n3e6DA8YqquS",
            },
            {
                "address": "12Gq5N1tDRUx7Tn7nEgHunazoAcDK1p6sw",
                "priv_key": "5KkKGuZgFTB5LCxcv9TiUtLEYSj9cYPeZ6xrK34YkpQpdKRdmkL",
            },
            {
                "address": "1L828t7SY3qzpKf3u3LfNNVvUHKtcQxBk8",
                "priv_key": "5JEUjCFHNgkA5LHtWD6fKeCGEuyo4gNvqgbjNdYDRB3RYHGzgUC",
            },
        ],
    },
    {
        "seed": b"d274ee3d2f0ca429e9b4cff307bcdc81ab503adc838b552123a1cf7d908a275b",
        "master_pub_key": "041bc0ddce2ac75a2d624316ad40d4031d710a16423830dc16d0b3423ee1fa946af8ce5987f6dba0d0078d9c3193373d01456abfd7f65b6c95d42ef3a24a5fba3d",
        "master_priv_key": "5KQyR8zmHmhEKjkHDpSFEPUKzaeFocywbpsjMN2rxDrRsdtSpDV",
        "addresses": [
            {
                "address": "18W9NHvXtxvs8macnQXTWbPb9nZtd98ydD",
                "priv_key": "5K6m9kA5ezpaR6tknSZWUirJ2x3bT5UovGRjYpX1bXB1yPKpM7G",
            },
            {
                "address": "1AswJdBRHVkKyBDWRDdrq3TQBD8JepFkxz",
                "priv_key": "5JU93eDB9HPGScrAVg2HV1G3c8MAwM9qKV8V86LgaLNQFS8Nsk8",
            },
            {
                "address": "14QJ1CFM9FfeWWs8f5XxUtWdngvShpTDHJ",
                "priv_key": "5JDh1pduCcxmkX1NbuFH9SPoyNRKTFR9FW7NH5yUPHhKGppKWD5",
            },
            {
                "address": "198qDpuez1ez26jx3YEcKG3HLbJfQGs7oS",
                "priv_key": "5JdQiFK7Az8Yhqrof3aDfu5WnPzv1vHAvMtJaCgjVqHcGrCtTp3",
            },
            {
                "address": "19csUz4nzBrJk8xq4yos3tS545H5u5SbrQ",
                "priv_key": "5JkcxTjBvmz4nbtT1xGNXGqvZoXaMU2zn292HEptXsYYKt2XKoZ",
            },
        ],
    },
]

# Generic seed for testing
TEST_SEED = b"\x01" * Secp256k1PrivateKey.Length()


#
# Tests
#
class ElectrumV1Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            # Test all types of construction
            self.__test_wallet(
                ElectrumV1.FromSeed(binascii.unhexlify(test["seed"])), False, test
            )
            self.__test_wallet(
                ElectrumV1.FromPrivateKey(self.__wif_to_priv(test["master_priv_key"])), False, test
            )
            self.__test_wallet(
                ElectrumV1.FromPublicKey(binascii.unhexlify(test["master_pub_key"])), True, test
            )

    # Test invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, ElectrumV1, TEST_ED25519_PRIV_KEY, None)
        self.assertRaises(TypeError, ElectrumV1, None, TEST_ED25519_PUB_KEY)

        invalid_index = Bip32KeyDataConst.KEY_INDEX_MAX_VAL + 1

        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetPrivateKey, invalid_index, 0)
        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetPrivateKey, 0, invalid_index)

        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetPublicKey, invalid_index, 0)
        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetPublicKey, 0, invalid_index)

        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetAddress, invalid_index, 0)
        self.assertRaises(ValueError, ElectrumV1.FromSeed(TEST_SEED).GetAddress, 0, invalid_index)

    # Test wallet
    def __test_wallet(self, electrum_v1, is_public_only, test):
        self.assertEqual(is_public_only, electrum_v1.IsPublicOnly())

        if not electrum_v1.IsPublicOnly():
            self.assertTrue(isinstance(electrum_v1.MasterPrivateKey(), Secp256k1PrivateKey))
            self.assertEqual(test["master_priv_key"], self.__priv_to_wif(electrum_v1.MasterPrivateKey()))
        else:
            self.assertRaises(ValueError, electrum_v1.MasterPrivateKey)

        self.assertTrue(isinstance(electrum_v1.MasterPublicKey(), Secp256k1PublicKey))
        self.assertEqual(test["master_pub_key"], electrum_v1.MasterPublicKey().RawUncompressed().ToHex())

        for i, test_addr in enumerate(test["addresses"]):
            if not electrum_v1.IsPublicOnly():
                self.assertEqual(test_addr["priv_key"], self.__priv_to_wif(electrum_v1.GetPrivateKey(0, i)))
                self.assertTrue(isinstance(electrum_v1.GetPrivateKey(0, i), Secp256k1PrivateKey))
            else:
                self.assertRaises(ValueError, electrum_v1.GetPrivateKey, 0, i)

            self.assertTrue(isinstance(electrum_v1.GetPublicKey(0, i), Secp256k1PublicKey))
            self.assertEqual(test_addr["address"], electrum_v1.GetAddress(0, i))

    # Decode WIF to private key
    @staticmethod
    def __wif_to_priv(priv_key):
        return WifDecoder.Decode(priv_key,
                                 CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"))[0]

    # Encode private key to WIF
    @staticmethod
    def __priv_to_wif(priv_key):
        return WifEncoder.Encode(priv_key,
                                 CoinsConf.BitcoinMainNet.ParamByKey("wif_net_ver"),
                                 WifPubKeyModes.UNCOMPRESSED)
