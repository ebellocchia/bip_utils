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

from bip_utils import MoneroPrivateKey, MoneroPublicKey, MoneroSubaddress
from bip_utils.monero.monero_subaddr import MoneroSubaddressConst


# Test vector
TEST_VECT = [
    {
        "priv_vkey": b"dc040dc3333460dccdc61e77a16f4c31e5f3d965c9c93efec425218c733b5400",
        "pub_skey": b"53f1cf5d17cecbd395ddee631b8ef0006366f5839e6e5c4ef5a0673b1923c2bf",
        "addr_net_ver": b"\x12",
        "sub_addr_net_ver": b"\x2a",
        "subaddress": [
            {
                "minor_idx": 0,
                "major_idx": 0,
                "pub_skey": "53f1cf5d17cecbd395ddee631b8ef0006366f5839e6e5c4ef5a0673b1923c2bf",
                "pub_vkey": "82859fdd5c8c76e397b70e0949c39a28613bd1e6fa174b2096949107d220caa8",
                "subaddress": "44ocYoMADLecPeL3taj8ij14mUqrn3rQ3ED1Lh1ids1BZ2tMfhyc2Dbf4w9shy6i5f7kjcxT4xsXp6T9VWKuqZzZKyQef6P",
            },
            {
                "minor_idx": 1,
                "major_idx": 0,
                "pub_skey": "99078fe5c9c6b25b10edf040c697927203a3613ec02b9668b991acbb82916569",
                "pub_vkey": "750bc332694499dfbb89d7dedc4013eaa7abeea494eef600e00491a2704f6fdd",
                "subaddress": "88FbsUdLqFoGETRSbW4h69L55gPRSvY77JWxptPQnQfNJe4tYKKh5YceRVCbzhn3jYgFSw8338z8d19VNuv9GKo4S1Knxbz",
            },
            {
                "minor_idx": 0,
                "major_idx": 1,
                "pub_skey": "03ff2a7360bb5e5d44780c637c793ee7d6c40af0b3bdfce7d69fb9bbde216596",
                "pub_vkey": "8f6c3b17f3631fc81c6a004c4272f3487fa230131f3756d4e8241649328f8c21",
                "subaddress": "82c36HvKeDKGbp3kXhDSDbfn8RftU5gpjfn87axpue7eSBd8hVtMpYnaUKz2Na3niND8Kxo1cqwcZccTqQKzEa2P4oQniWx",
            },
            {
                "minor_idx": 1,
                "major_idx": 1,
                "pub_skey": "17fb00ce8e373b5370138a2b65c2657a1634bb0d29c15a4368f721a78d61444a",
                "pub_vkey": "f7aae35cdf39b633b11c7da09c52bf975c0c9dfd91f2b7f40b256c94eae836b0",
                "subaddress": "83MxdUKPHvAExTAhq8def6MRPsXcVJ1GmCGxmyKu3MMVDYH8pMR5EXw9eUax6c7GvaSKNtbNhoEqthpXdKS2VMyfLueHY1A",
            },
        ],
    },
    {
        "priv_vkey": b"44754b4be2bfe25dbb0d48341a34b6671b96dfc62659800e3e6a3d59c80a950b",
        "pub_skey": b"708e54bdee993949706537a7f0b9f9e519680c2b688560ee3b1d10f8b9de9fe5",
        "addr_net_ver": b"\x12",
        "sub_addr_net_ver": b"\x2a",
        "subaddress": [
            {
                "minor_idx": 0,
                "major_idx": 0,
                "pub_skey": "708e54bdee993949706537a7f0b9f9e519680c2b688560ee3b1d10f8b9de9fe5",
                "pub_vkey": "494b0dc9e2db16e36a7e2ffcdd31cd178bf46419d4243d5678b50a9aa4bb54b4",
                "subaddress": "45tVwrfdxV6DHT9EoFa9fvfKYt1kDPr55gr928yHdhEnfMN8e7oHY4mf3Dkw5eALT64wS5p7wXLTWFTtA1kqA22oMM5Gek3",
            },
            {
                "minor_idx": 1,
                "major_idx": 0,
                "pub_skey": "628a9bf3e70cc084be6c8f29fe2a37ef39e267264ff362c391ab66a68d3e7c57",
                "pub_vkey": "29de0f298a9401c5b6a65abf47566a6151684d2a7a48b08dad38f97a3707a834",
                "subaddress": "86BqhYtMUw9PCnLCMpi4y4h1nzTaJ2byKZiGLk4fMcgTFabYVVhYABaa54y38HoXhKHH7BDGJiqPVQhSaTwgMUoZ6ykTGoy",
            },
            {
                "minor_idx": 0,
                "major_idx": 1,
                "pub_skey": "d8c6873d62e1f1e15a8111e8164be7004d217b56871ff8656219eab510fdf69d",
                "pub_vkey": "b466b91a9ddbca1299858007cafde6e0a2b74b9e624bd364d026db592d9b9a41",
                "subaddress": "8AfiErPGPk4ehDGeo1SUHL13vXg3kqDTuHxYZQMuYDgRTNw7qGtqrXB47SYFV3AvLVeaFKEomAzanHs1mh2cj7Zb8QoN8dF",
            },
            {
                "minor_idx": 1,
                "major_idx": 1,
                "pub_skey": "75caaac8ded802576a3fd6910d332bb703488f548a602111f76894ae204e40ec",
                "pub_vkey": "2989e6dda6fea2d406d9b0bd9ed452da183d229552fefb21a8296d9d27c8a9b8",
                "subaddress": "86v9jEBBbnyFd33wH6AJM8XcTK82hfaHE41JE1EQKProgW53f7RkjAycTvfEki1EphdUnv1avXowg6dWopQ2B66LMoDSf7t",
            },
        ],
    },
]

# Keys for testing
TEST_PRIV_VIEW_KEY = b"dc040dc3333460dccdc61e77a16f4c31e5f3d965c9c93efec425218c733b5400"
TEST_PUB_SPEND_KEY = b"53f1cf5d17cecbd395ddee631b8ef0006366f5839e6e5c4ef5a0673b1923c2bf"


#
# Tests
#
class MoneroSubaddrTests(unittest.TestCase):
    # Test compute
    def test_compute(self):
        for test in TEST_VECT:
            # Get keys
            priv_vkey = MoneroPrivateKey.FromBytes(binascii.unhexlify(test["priv_vkey"]))
            pub_skey = MoneroPublicKey.FromBytes(binascii.unhexlify(test["pub_skey"]))

            # Create object
            monero_subaddr = MoneroSubaddress(priv_vkey, pub_skey)

            for test_subaddr in test["subaddress"]:
                # ComputeKeys
                pub_skey, pub_vkey = monero_subaddr.ComputeKeys(test_subaddr["minor_idx"], test_subaddr["major_idx"])
                self.assertEqual(test_subaddr["pub_skey"], pub_skey.RawCompressed().ToHex())
                self.assertEqual(test_subaddr["pub_vkey"], pub_vkey.RawCompressed().ToHex())

                # ComputeAndEncodeKeys
                net_ver = (test["addr_net_ver"]
                           if test_subaddr["minor_idx"] == test_subaddr["major_idx"] == 0
                           else test["sub_addr_net_ver"])
                subaddr = monero_subaddr.ComputeAndEncodeKeys(test_subaddr["minor_idx"], test_subaddr["major_idx"], net_ver)
                self.assertEqual(test_subaddr["subaddress"], subaddr)

    # Test invalid parameters
    def test_invalid_params(self):
        priv_vkey = MoneroPrivateKey.FromBytes(binascii.unhexlify(TEST_PRIV_VIEW_KEY))
        pub_skey = MoneroPublicKey.FromBytes(binascii.unhexlify(TEST_PUB_SPEND_KEY))

        monero_subaddr = MoneroSubaddress(priv_vkey, pub_skey)

        self.assertRaises(ValueError, monero_subaddr.ComputeKeys, -1, 0)
        self.assertRaises(ValueError, monero_subaddr.ComputeKeys, 0, -1)
        self.assertRaises(ValueError, monero_subaddr.ComputeKeys, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1, 0)
        self.assertRaises(ValueError, monero_subaddr.ComputeKeys, 0, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1)

        self.assertRaises(ValueError, monero_subaddr.ComputeAndEncodeKeys, -1, 0, b"")
        self.assertRaises(ValueError, monero_subaddr.ComputeAndEncodeKeys, 0, -1, b"")
        self.assertRaises(ValueError, monero_subaddr.ComputeAndEncodeKeys, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1, 0, b"")
        self.assertRaises(ValueError, monero_subaddr.ComputeAndEncodeKeys, 0, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1, b"")
