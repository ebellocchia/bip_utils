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
import binascii
import unittest

from bip_utils import Base58ChecksumError, Bip38Decrypter, Bip38EcKeysGenerator, Bip38Encrypter, Bip38PubKeyModes
from bip_utils.bip.bip38.bip38_ec import Bip38EcConst


# Tests for decoding from BIP38 page (with EC multiplication)
# https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
TEST_VECT_DEC = [
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "TestingOneTwoThree",
        "priv_key_bytes": b"a43a940577f4e97f5c4d39eb14ff083a98187c64ea7c99ef7ce460833959a519",
        "encrypted": "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "Satoshi",
        "priv_key_bytes": b"c2c8036df268f498099350718c4a3ef3984d2be84618c2650f5171dcc5eb660a",
        "encrypted": "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "MOLON LABE",
        "priv_key_bytes": b"44ea95afbf138356a05ea32110dfd627232d0f2991ad221187be356f19fa8190",
        "encrypted": "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "ΜΟΛΩΝ ΛΑΒΕ",
        "priv_key_bytes": b"ca2759aa4adb0f96c414f36abeb8db59342985be9fa50faac228c8e7d90e3006",
        "encrypted": "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
    },
]

# Tests for encoding from BIP38 page (with EC multiplication)
TEST_VECT_ENC = [
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "TestingOneTwoThree",
        "lot_num": None,
        "seq_num": None,
    },
    {
        "pub_key_mode": Bip38PubKeyModes.COMPRESSED,
        "passphrase": "TestingOneTwoThree",
        "lot_num": None,
        "seq_num": None,
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "passphrase": "TestingOneTwoThree",
        "lot_num": 100000,
        "seq_num": 1,
    },
    {
        "pub_key_mode": Bip38PubKeyModes.COMPRESSED,
        "passphrase": "TestingOneTwoThree",
        "lot_num": 100001,
        "seq_num": 2,
    }
]

# Tests for invalid encrypted strings
TEST_VECT_DEC_INVALID = {
    Base58ChecksumError: [
        "6PfXER1HkxBryQDU3iukCt6ASDH4KmXiLN9ukLuFpY45PFPvacKqX5QrLn",
        "6PnWzB9iU2fftjn1BcnMEGDefCfZHqCJNLcntxSnVoH7EiaQ32DnzG5rCG",
    ],
    ValueError: [
        # Invalid base58 encoding
        "6PflGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        "6PgGWtx25kUg8QWvwuJAgOrN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
        # Invalid length
        "2DsBJdAmt8SxyPV1vGDco4ZA61tCLfK9AoKdxMhWQpPqWF4SPGXJ748Vz",
        "QoZvdXXE7NRr3A7fN4ggxZg3vRje28mQKeWXpDXAinaaaikkMtmdZBPWu2i",
        # Invalid prefix
        "6Qkh8pdHhKVwawiiMhxDGXzWqmy25L8BHr1GsoSFXVFKvpxtSz9dvx7ecE",
        # Invalid flagbyte
        "6PniVNh9a23BzarikZQphPJr3JnwPksaUByrH9TVkoyztCpJ1RhDZ4xAYH",
        "6PnuCXqo9z6LTBtCzCiLped1Y5wRc2EcicC3cwH7fpMwxsmYXzuk6W8ogs",
        # Invalid address hash
        "6PnNkEe2haex3HfxCfiKVi3VzGYrAKZGCCk55ZJbAEVh4ECZBhkVogqTVC",
    ],
}

# Tests for invalid intermediate passphrases
TEST_VECT_INT_PASS_INVALID = {
    Base58ChecksumError: [
        "passphraseqoXNk7sefXMWWJkQ8E9LMYAjQvcEJzT8eW1YyEF6K55mJuUS8xWr9qZyZjQSjx",
        "passphrasepkHGy593DTmXYG1mnYe6zLqjTV6LB7hMc7B29odQpQwNWTtWbQTUXScNYcVMzc",
    ],
    ValueError: [
        # Invalid base58 encoding
        "passphraserOrNyd6mzi6Y8qjxGM7oRUZ7UjWdeX4xKgSinMqtmxRYbFkNHj8u9uBAChNtqx",
        "passphrasepglJNTNH41c7K5umSnve7QK4uvAXe7HqzZzKomYtf2NT3DiweKvCebGFsiMzTQ",
        # Invalid length
        "BnHWe6BL19ZNRVsZkibpyb7FcZ7VKQpr3eSr6cT9BEVFMyJrR9QFeUxGKKxC7tmz2XF3aTQ",
        "4d2XZKZKrWZuKrUWc6qjvdsfTC1MBD4E7Fq761NTBJ9QGhkxgDCYHNGEJXQ78MnE5LyiZ8rAuL",
        # Invalid magic
        "passphrasehfUHDug6znQzhCVmsawWEZT5kykEDAftfUUFVpSxeFeFcWYFvr7swKCvAnXwy9",
    ]
}


#
# Tests
#
class Bip38EcTests(unittest.TestCase):
    # Run all tests in test vector for decoding
    def test_vector_dec(self):
        for test in TEST_VECT_DEC:
            dec, pub_key_mode = Bip38Decrypter.DecryptEc(test["encrypted"], test["passphrase"])
            self.assertEqual(test["priv_key_bytes"], binascii.hexlify(dec))
            self.assertEqual(test["pub_key_mode"], pub_key_mode)

    # Run all tests in test vector for encoding
    def test_vector_enc(self):
        for test in TEST_VECT_ENC:
            # The generated private keys are random, so the encrypted keys canot be checked against predefined ones
            # So, we generate the encrypted private keys and then we simply decrypt them
            # If everything is fine, no exception will be raised by the DecryptEc method
            enc = Bip38Encrypter.GeneratePrivateKeyEc(test["passphrase"], test["pub_key_mode"], test["lot_num"], test["seq_num"])
            dec, pub_key_mode = Bip38Decrypter.DecryptEc(enc, test["passphrase"])
            self.assertEqual(test["pub_key_mode"], pub_key_mode)

    # Test invalid for decoding
    def test_dec_invalid(self):
        for ex, tests in TEST_VECT_DEC_INVALID.items():
            for test in tests:
                # "with" is needed because some exceptions are raised by Base58 module
                with self.assertRaises(ex):
                    Bip38Decrypter.DecryptEc(test, "")

    # Test invalid for intermediate passphrase
    def test_int_pass_invalid(self):
        for ex, tests in TEST_VECT_INT_PASS_INVALID.items():
            for test in tests:
                # "with" is needed because some exceptions are raised by Base58 module
                with self.assertRaises(ex):
                    Bip38EcKeysGenerator.GeneratePrivateKey(test, Bip38PubKeyModes.COMPRESSED)

    # Test invalid lot/sequence numbers for intermediate passphrase
    def test_int_pass_invalid_lot_seq(self):
        self.assertRaises(ValueError, Bip38EcKeysGenerator.GenerateIntermediatePassphrase, "", Bip38EcConst.LOT_NUM_MIN_VAL - 1, Bip38EcConst.SEQ_NUM_MIN_VAL)
        self.assertRaises(ValueError, Bip38EcKeysGenerator.GenerateIntermediatePassphrase, "", Bip38EcConst.LOT_NUM_MAX_VAL + 1, Bip38EcConst.SEQ_NUM_MIN_VAL)
        self.assertRaises(ValueError, Bip38EcKeysGenerator.GenerateIntermediatePassphrase, "", Bip38EcConst.LOT_NUM_MIN_VAL, Bip38EcConst.SEQ_NUM_MIN_VAL - 1)
        self.assertRaises(ValueError, Bip38EcKeysGenerator.GenerateIntermediatePassphrase, "", Bip38EcConst.LOT_NUM_MIN_VAL, Bip38EcConst.SEQ_NUM_MAX_VAL + 1)
