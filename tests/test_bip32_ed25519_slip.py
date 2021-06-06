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
from bip_utils import Bip32Ed25519Slip, Bip32KeyError, Bip32Utils

# Tests from BIP32 and SLIP-0010 pages
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFybaNRzmKwjLEeQdU4ciWTZ1zPxvvN683xNT57Gr2k7Ybe5sLdMAtszjE1cd1Q1Wmb82QjvjtYomxGdbfLN5wnDyCpd3t6e",
            "ex_priv": "xprv9s21ZrQH143K3VX7GQTkxonbgca94bts9EdRC1ZKN2Z9BA3JXZxbUwo4kS28ECmXhK1NicjQ7yBwWbZXgjRVktP6Tzi4YqetK5ueSA2CaXP",
            "pub_key": "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
            "priv_key": "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            "chain_code": b"90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            "parent_fprint": b"00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32Utils.HardenIndex(0),
                "ex_pub": "xpub69X73wc3Gk79HaBpGavu6teUN7tZmjSxrg5sMVkT8uRuYUeQknJAZubqnJCeGqq5Tm1SamntUPcnAAkLaZMjXjAHBM85e5L4bV3HebS74ou",
                "ex_priv": "xprv9vXkeS59SNYr567MAZPtjkhjp645NGj7VTAGZ7LqaZtvfgKGDEyv27HMw6nfHWcSnKnJ6BtTKrhgsKUkxtR3K6juACC8Qw4DRWr7hrAJxKX",
                "pub_key": "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                "priv_key": "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "chain_code": b"8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                "parent_fprint": b"ddebc675",
            },
            # m/0'/1'
            {
                "path": "m/0'/1'",
                "index": Bip32Utils.HardenIndex(1),
                "ex_pub": "xpub69v6c75HWiC1VRZegct9DEKCmM6m4K7SS6xMQDZumr3aUaRGmoNpKkKJgHdVR1RL6VjDxUBWyRAJwJLPbBQmEvnT7k9MSXinpyGcWTDKPPt",
                "ex_priv": "xprv9vvkCbYPgLdiGwVBabM8r6NUDKGGerPb4t2kbqAJDWWbbn68EG4Zmwzpq7eRjbQ78MFnnyasFqt9WiEEnVBpE878KQB3fxYjCkUcUjLBXjg",
                "pub_key": "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                "priv_key": "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "chain_code": b"a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                "parent_fprint": b"13dab143",
            },
            # m/0'/1'/2'
            {
                "path": "m/0'/1'/2'",
                "index": Bip32Utils.HardenIndex(2),
                "ex_pub": "xpub6DPLFvLFWQVt6kb2ZH5XDkd4hv5NX8Je9e9T5qQ8fuUt9dn8yKSNHSk4K5bBvr3j4VcTF2zJoWanvQf59zz4FDokFj5mNHUqdgXj5z4s4mz",
                "ex_priv": "xprv9zPyrQoMg2watGWZTFYWrcgL9tEt7fannRDrHSzX7ZwuGqSzRn87jeRaTtEbwReQdnWzWDk82R6o13r56u9Q9w6WecqiswiQbsknzXnEnCR",
                "pub_key": "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                "priv_key": "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "chain_code": b"2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                "parent_fprint": b"ebe4cb29",
            },
            # m/0'/1'/2'/2'
            {
                "path": "m/0'/1'/2'/2'",
                "index": Bip32Utils.HardenIndex(2),
                "ex_pub": "xpub6DtygH5C84WTLFcVZGtesPrjgmE4LWXpPqbfzRc2xH2q9nBxRyPBmYHNN5ckfXGLJjMXc2BPePB5PzJFJypfftX21G3eJYWVzpSF899Nxeq",
                "ex_priv": "xprv9zudGmYJHgxA7mY2TFMeWFv18jPZw3oy2cg5C3CRPwVrGyrotS4wDjxtWsnswR7mmG1ysEZBVZscqbymKaGCQkbiA6QEka9tBALGqmt4d2w",
                "pub_key": "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                "priv_key": "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "chain_code": b"8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                "parent_fprint": b"316ec1c6",
            },
            # m/0'/1'/2'/2'/1000000000'
            {
                "path": "m/0'/1'/2'/2'/1000000000'",
                "index": Bip32Utils.HardenIndex(1000000000),
                "ex_pub": "xpub6GzMUbGykK9tAV4LW8nQv4RFefFkSr75D9uX5FUKxy5UgYE16xnXdEc8XCWbqMD6vzQDvf7BDsQ3yvoWS3VPVVTSwpxyncSJxXpdJBfP7bh",
                "ex_priv": "xprvA41155k5uwbawzysQ7FQYvUX6dRG3PPDqvyvGs4iQdYVojtrZRUH5SHeg2153NJCehKfTCRcJj2JYhtZnZunAhM6U6JsTdEhB5h6dxH3dg4",
                "pub_key": "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                "priv_key": "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "chain_code": b"68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                "parent_fprint": b"d6322ccd",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcGvhV67CLpH9pkuL15VmcXENpThobsvTXHrSRZ9cq4oRJS3sTEY93ZJeoRxEdEofbMdPYQRWixwx2aFSWV51s3n2NQbe4oqt",
            "ex_priv": "xprv9s21ZrQH143K4Sd1z5fLT9D6CsVWg33mA1TDfKPzKavYR47H1cJaX16paqoyUuw3g1Zm6GHruGNpXqdVk8BVoZ8bLE3DYQpudN4C9H391kJ",
            "pub_key": "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
            "priv_key": "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            "chain_code": b"ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
            "parent_fprint": b"00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32Utils.HardenIndex(0),
                "ex_pub": "xpub68Fe6ZgoZxMb3t75vAQS8c74jUjFY6NdJEwkYJu1majwZLtjpEziLsSn9bWYgvf5Uv6JzZZZHZJpo431VZhjXdehLdTdYaRyXLF7w24AkYs",
                "ex_priv": "xprv9uGHh49ujaoHqQ2cp8sRmUALBStm8demw229jvVQDFCxgYZbGhgTo58JJPWE84Yqukks3CEsoUX1T61y5r6pMh59woxdZbncKbJsHSMbq42",
                "pub_key": "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                "priv_key": "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                "chain_code": b"0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                "parent_fprint": b"31981b50",
            },
            # m/0'/2147483647'
            {
                "path": "m/0'/2147483647'",
                "index": Bip32Utils.HardenIndex(2147483647),
                "ex_pub": "xpub69zfmfjKFbnc5LoQcKFntZjyNGHY1cfX8QZg57LdJEgDBUGnegMhsUtTzWbmbPJ8bwhk9wAv4Pb27p7tXpg14EdjtQzzj4GGFQXfUhGA9X6",
                "ex_priv": "xprv9w1KNACRREEJrriwWHinXRoEpET3c9wfmBe5Giw1ju9EJfwe793TKgZz9LYKq4cJoMpoBzTAToDFv7GctoZnpBoSEHRaCPpubaCLeqXanCu",
                "pub_key": "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                "priv_key": "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "chain_code": b"138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                "parent_fprint": b"1e9411b1",
            },
            # m/0'/2147483647'/1'
            {
                "path": "m/0'/2147483647'/1'",
                "index": Bip32Utils.HardenIndex(1),
                "ex_pub": "xpub6DWVJYGb5VkTBCSegY9Axga63jEueUpArXsd6FquQp72rwxx9CaUimhZY1YcfWS4PrZijf3kgPDHBK4LzWxs5Zp9ao3TkXCnFJqGH3vaCLw",
                "ex_priv": "xprv9zX8u2jhF8C9xiNBaWcAbYdMVhQRF26KVJx2HsSHrUa3z9dobfGEAyP5gpUGyyCecurJkGKZWq15f1L4UYcfcVnoMmzwoXaH3ghtQwq4soQ",
                "pub_key": "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                "priv_key": "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                "chain_code": b"73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                "parent_fprint": b"fcadf38c",
            },
            # m/0'/2147483647'/1'/2147483646'
            {
                "path": "m/0'/2147483647'/1'/2147483646'",
                "index": Bip32Utils.HardenIndex(2147483646),
                "ex_pub": "xpub6EoWQuRXaaCFHjnD2q5aBQZUbXWxSjc2AkA77KvP1LcuYqPgC5fiiiFUvrF17PCqcyfR6sG8G13RmjbNvmuHzqvrBZY335vCKS9NxhA1ygr",
                "ex_priv": "xprvA1pA1PtdkCdx5FhjvoYZpGck3VgU3GtAoXEWJwWmT15vg34XeYMUAuw15e3VzZYnvSFERzrB4Pih42T1D7WFmNmN5Y1S77jdY2PWZoSGjLd",
                "pub_key": "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                "priv_key": "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                "chain_code": b"0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                "parent_fprint": b"aca70953",
            },
            # m/0'/2147483647'/1'/2147483646'/2'
            {
                "path": "m/0'/2147483647'/1'/2147483646'/2'",
                "index": Bip32Utils.HardenIndex(2),
                "ex_pub": "xpub6FuFU9pp1pkZdD8zxzXtoRykbHUxmXPZd3GzLie25z4559c7PUmoMHWopp2h5KfxEyWUdL1bNPxncaNmxdzf3qpLA3eJhdgHWb1xf4Mc7Ff",
                "ex_priv": "xprvA2uu4eHvBTCGQj4XrxztSJ323FeUN4fiFpMPYLEQXeX6CMGxqwTYoVCKyczbQmhPTHN4J3MxfvSu3pPCKRmG5SbooBcnq3TUCLvZ417Cspw",
                "pub_key": "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                "priv_key": "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                "chain_code": b"5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                "parent_fprint": b"422c654b",
            },
        ],
    },
]

# Tests for invalid seeds
TEST_VECT_SEED_ERR = [
    b"000102030405060708090a0b0c0d0e",
    b"000102030405060708090a0b0c0d",
]


#
# Bip32Ed25519Slip tests
#
class Bip32Ed25519SlipTests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        for test in TEST_VECT:
            # Create from seed
            bip32_ctx = Bip32Ed25519Slip.FromSeed(binascii.unhexlify(test["seed"]))
            # Test master key
            self.assertEqual(test["master"]["index"], int(bip32_ctx.Index()))

            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            self.assertEqual(test["master"]["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
            self.assertEqual(test["master"]["pub_key"], str(bip32_ctx.PublicKey().RawCompressed()))
            self.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode("utf-8")), bip32_ctx.PublicKey().RawCompressed().ToBytes())
            self.assertEqual(binascii.unhexlify(test["master"]["pub_key"].encode("utf-8")), bytes(bip32_ctx.PublicKey().RawCompressed()))

            self.assertEqual(test["master"]["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
            self.assertEqual(test["master"]["priv_key"], str(bip32_ctx.PrivateKey().Raw()))
            self.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode("utf-8")), bip32_ctx.PrivateKey().Raw().ToBytes())
            self.assertEqual(binascii.unhexlify(test["master"]["priv_key"].encode("utf-8")), bytes(bip32_ctx.PrivateKey().Raw()))

            self.assertEqual(test["master"]["chain_code"], binascii.hexlify(bip32_ctx.ChainCode()))
            self.assertEqual(test["master"]["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))
            self.assertEqual(test["master"]["parent_fprint"], binascii.hexlify(bytes(bip32_ctx.ParentFingerPrint())))

            # Test derivation paths
            for chain in test["der_paths"]:
                # Update context
                bip32_ctx = bip32_ctx.ChildKey(chain["index"])
                # Test keys
                self.assertEqual(chain["index"], int(bip32_ctx.Index()))

                self.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

                self.assertEqual(chain["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
                self.assertEqual(chain["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())

                self.assertEqual(chain["chain_code"], binascii.hexlify(bip32_ctx.ChainCode()))
                self.assertEqual(chain["parent_fprint"], binascii.hexlify(bip32_ctx.ParentFingerPrint().ToBytes()))
                self.assertEqual(chain["parent_fprint"], binascii.hexlify(bytes(bip32_ctx.ParentFingerPrint())))

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        for test in TEST_VECT:
            # Create from seed
            bip32_ctx = Bip32Ed25519Slip.FromSeed(binascii.unhexlify(test["seed"]))
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for chain in test["der_paths"]:
                # Update context
                bip32_from_path = bip32_ctx.DerivePath(chain["path"][2:])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        for test in TEST_VECT:
            # Create from seed
            bip32_ctx = Bip32Ed25519Slip.FromSeedAndPath(binascii.unhexlify(test["seed"]), "m")
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Test derivation paths
            for chain in test["der_paths"]:
                # Try to build from path and test again
                bip32_from_path = Bip32Ed25519Slip.FromSeedAndPath(binascii.unhexlify(test["seed"]), chain["path"])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_from_path.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_from_path.PrivateKey().ToExtended())

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        for test in TEST_VECT:
            # Create from private extended key
            bip32_ctx = Bip32Ed25519Slip.FromExtendedKey(test["master"]["ex_priv"])
            # Test master key
            self.assertEqual(test["master"]["ex_pub"], bip32_ctx.PublicKey().ToExtended())
            self.assertEqual(test["master"]["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

            # Same test for derivation paths
            for chain in test["der_paths"]:
                # Create from private extended key
                bip32_ctx = Bip32Ed25519Slip.FromExtendedKey(chain["ex_priv"])
                # Test keys
                self.assertEqual(chain["ex_pub"], bip32_ctx.PublicKey().ToExtended())
                self.assertEqual(chain["ex_priv"], bip32_ctx.PrivateKey().ToExtended())

    # Test invalid seed
    def test_invalid_seed(self):
        for test in TEST_VECT_SEED_ERR:
            self.assertRaises(ValueError, Bip32Ed25519Slip.FromSeed, binascii.unhexlify(test))

    # Test invalid derivation
    def test_invalid_derivation(self):
        seed_bytes = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f")
        bip32_ctx = Bip32Ed25519Slip.FromSeed(seed_bytes)

        # Not-hardened private derivation
        self.assertRaises(Bip32KeyError, Bip32Ed25519Slip.FromSeedAndPath, seed_bytes, "m/0'/1")
        self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, 0)
        self.assertRaises(Bip32KeyError, bip32_ctx.DerivePath, "0'/1")

        # Public derivation
        bip32_ctx.ConvertToPublic()
        self.assertRaises(Bip32KeyError, bip32_ctx.ChildKey, 0)
