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

from bip_utils import Bip38PubKeyModes, Secp256k1PublicKey
from bip_utils.bip.bip38.bip38_addr import Bip38Addr


# Public keys for testing
TEST_VECT = [
    {
        "pub_key_mode": Bip38PubKeyModes.COMPRESSED,
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_hash": b"a374deb6",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "pub_key": b"03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "address_hash": b"6a531625",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.COMPRESSED,
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_hash": b"97c1e671",
    },
    {
        "pub_key_mode": Bip38PubKeyModes.UNCOMPRESSED,
        "pub_key": b"02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "address_hash": b"8805ef61",
    },
]


#
# Tests
#
class Bip38AddrTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            key_bytes = binascii.unhexlify(test["pub_key"])
            address_hash = Bip38Addr.AddressHash(Secp256k1PublicKey.FromBytes(key_bytes), test["pub_key_mode"])
            self.assertEqual(test["address_hash"], binascii.hexlify(address_hash))
