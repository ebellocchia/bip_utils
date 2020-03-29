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
from bip_utils import P2PKH


# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "pub_key"    : b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
            "address"    :  "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            "is_testnet" :  False,
        },
        {
            "pub_key"    : b"037fd6980d7627cf664236cec772ec78cf52cb357952e35e73e31afbe4b2810d80",
            "address"    :  "146emAmGumhnsT9nPCALU2JWeS4koxfFRB",
            "is_testnet" :  False,
        },
        {
            "pub_key"    : b"02e105442a111f898b3a03bb0ca7d8cffc72c3e307d06c22d0ec28b058e620ae39",
            "address"    :  "18xPZpJUxJhuhTyysVEwJAAoYUwX5T3cFV",
            "is_testnet" :  False,
        },
        {
            "pub_key"    : b"02a38046d4abdbfe4df3ef1188d0df28613041121c44fb5f61cff79574dbca40ab",
            "address"    :  "19hp5PzFjsD6z1hwMucUbLHAYeYDWdvB1B",
            "is_testnet" :  False,
        },
        {
            "pub_key"    : b"02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
            "address"    :  "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
            "is_testnet" :  True,
        },
        {
            "pub_key"    : b"03e4d2ca5ec69260a80b5ee1a459522196afd38ed1e11476dee5fb08a6531a92b7",
            "address"    :  "myHL2QuECVYkx9Y94gyC6RSweLNnteETsB",
            "is_testnet" :  True,
        },
        {
            "pub_key"    : b"02d03accf6c5278d814e7cfa18edf548c5f8156713fc0c828db6abb44dea6483d3",
            "address"    :  "mp8ML8bKSiheUJPompTj5GZEWJUPmr1eiH",
            "is_testnet" :  True,
        },
        {
            "pub_key"    : b"03fb4c065bd39724eca1129ab1ccfce57ac58bcf8e7bdd037cfb28ddeabdd1702e",
            "address"    :  "n3Zb38sLaM21q8dwDNZq7AsJda9omg6PuP",
            "is_testnet" :  True,
        },
    ]


#
# Tests
#
class P2PKHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            # Test decoder
            self.assertEqual(test["address"], P2PKH.ToAddress(binascii.unhexlify(test["pub_key"]), test["is_testnet"]))
            self.assertEqual(test["address"], P2PKH.ToAddress(binascii.unhexlify(test["pub_key"]), test["is_testnet"]))


# Run test if executed
if __name__ == "__main__":
    unittest.main()
