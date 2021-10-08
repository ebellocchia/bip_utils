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
import unittest
from bip_utils import NanoAddr
from .test_addr_base import AddrBaseTestHelper
from .test_addr_const import *

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"0063b14c2b966809da4b4f90c53ee12633be9f708cbd834eb24012f9306f3e8f4a",
        "addr_params": {},
        "address": "nano_1rxjbioset1bub7nz6879uikeexymxrashe5bts616qs83qmx5tcxoeox6ms",
    },
    {
        "pub_key": b"0089624c7666f0b8004df74ef749a96991bb602273b41fec38e7190fcd2ebcb5f9",
        "addr_params": {},
        "address": "nano_34d4bju8fw7r138zgmqqb8npm6fue1j99f1zxiwgg8ahsnqdsfhsr6dyoimk",
    },
    {
        "pub_key": b"006bfef755481c161fcd56c7b7902193528a36b117563793cf02a374455e983dcf",
        "addr_params": {},
        "address": "nano_1tzyyxcni91p5z8ofjxqk1is8nnc8trjgojqkh9i7aunaohbihghw4edxiqj",
    },
    {
        "pub_key": b"8f3330f2d62eb3232b4d23d67193d37d9c61678d12445cc68620e0f648456788",
        "addr_params": {},
        "address": "nano_35sm85sfedom6eontaypg8bx8zewe7mrt6k6dm5aea91ys66cswa9bw9bg5f",
    },
    {
        "pub_key": b"1594ba7eecada3f311d52d84bc462a8398f4aac71d252cd4db79e946d5511f0d",
        "addr_params": {},
        "address": "nano_17enqbzgsdf5yeaxcde6qj54o1wrykoeg9b77mcfpyhbauco49rfwgzbact6",
    },
]


#
# Tests
#
class NanoAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, NanoAddr, Ed25519Blake2bPublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             NanoAddr,
                                             {},
                                             TEST_ED25519_BLAKE2B_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_ED25519_PUB_KEY_INVALID)
