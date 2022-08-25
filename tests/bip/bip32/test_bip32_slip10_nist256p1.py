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

from bip_utils import Bip32KeyIndex, Bip32Nist256p1, Bip32Slip10Nist256p1, EllipticCurveTypes
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import Bip32BaseTests
from tests.bip.bip32.test_bip32_slip10_secp256k1 import TEST_VECT_EX_KEY_ERR


# Tests from SLIP-0010 pages
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.NIST256P1,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcGSgS16avaQy74dApLYNUmG6oEuQdx6Kpt2VFxGUowawWaozRLQSe46f7nbyC5ZY8Tvvnc32WSiL3LSxFNvPgG84QVAyvBAw",
            "ex_priv": "xprv9s21ZrQH143K3xbxu53vDH2NWbLKw5edQ3BCSX12Pknr1EA7QjAZPnd2jYvGvZ9RSwbcfeCZ5v2qZTTESRMTiAizzfQ1GUDeMWPyaXGcMfF",
            "pub_key": "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
            "priv_key": "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
            "chain_code": "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub69Hf9HXFBywkLQytW4xV5qBozHcMX2naNRKWmC9gvtNLVsxfHUr3K8nAyWB6SFgSTJXtSoNqVPBjy5qeMcEb1EZhuPwUd7Sy2tSprcR3bN5",
                "ex_priv": "xprv9vJJjmzMMcPT7vuRQ3RUihF5SFms7a4j1CPuxok5NYqMd5dWjwXnmLTh8CzdBZJwHUybU3gSkKEAm86C27yde9ziL2PmahvMQSPhWSVAyVb",
                "pub_key": "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
                "priv_key": "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
                "chain_code": "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
                "parent_fprint": "be6105b5",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6AuiS2wva55Z7HWPpnFURRecui65CCed8ad267UvufRGapiWh7seGxoz4e9nu9G1aBYqGsEV5RjhqLAjNWm294RZTgU8UgQ821iaPY5tazr",
                "ex_priv": "xprv9wvN2XR2jhXFtoRvikiU4HhtMgFanjvmmMhRHj5KMKtHi2PN9aZPjAVWDLrjUbi5qejuMeQ3jH4ysGCVjVMMgERS3zCpv9DgbSEeHBnmR5k",
                "pub_key": "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
                "priv_key": "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
                "chain_code": "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
                "parent_fprint": "9b02312f",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6D1rDyWkGcRMNpCfFwYYhv7kCJyGi214QXZdkcHTetjjCBw4SqmeqAyQnj8zdxbg7xNC4JjE25XwWqxxEMKdx3vafV7J2FKJ6XEEi4hp3WE",
                "ex_priv": "xprv9z2VpTyrSEs4AL8C9v1YLnB1eH8nJZHD3Je2xDsr6ZCkKPbuuJTQHNevwSHHzswEQqojkg9RnGZPFTwUA4e9q83KCKiCu7cFr7T2gWLtdcu",
                "pub_key": "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
                "priv_key": "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
                "chain_code": "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
                "parent_fprint": "b98005c1",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6De8wqgw75HJZuSLEQyfqeDG5aiLjY2KSv11Mm2DLwDXr4pADQcFWvRA2LL7pvxk3ujEA6fki2SN7aSTSBJvA7pDesLw3xapFzYFzfhF1R8",
                "ex_priv": "xprv9zenYLA3Ghj1MRMs8PSfUWGXXYsrL5JU5h5QZNcbnbgYyGV1fsHzy86gB4mYtZYxSKppYHoxQzCrv4QU9VjVuiynQcpC8bDdEGoVFMAsuoS",
                "pub_key": "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
                "priv_key": "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
                "chain_code": "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
                "parent_fprint": "0e9f3274",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6GSNNH27v2EyJHApZumyLzxRTNkb2eUbLd1K1yhq8FLTU3XcRyzX4XnXMZmQnUwEEUAj4wLtQs6ePsffNJq9jf4nwCPgbjU3skwm3tBjEBn",
                "ex_priv": "xprvA3T1xmVE5egg5o6MTtExys1guLv6dBkjyQ5iDbJDZuoUbFCTtSgGWjU3WJjo8qstAV3pXygy91PAHKGA3UiZZCp8poRsezYt5etdF5AvQwJ",
                "pub_key": "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
                "priv_key": "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
                "chain_code": "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
                "parent_fprint": "8b2b5c4b",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.NIST256P1,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcG3WogcdvnYjkerPwRhXFiwqpKD4kiBX8sVng6fM3CJa5G4dUWuNtddwAc6hZTk5Mxzrr4YhLzryEpcGqcbqKPCmkV89g3j6",
            "ex_priv": "xprv9s21ZrQH143K3ZSLab6vRQo26pZT2EoQMivDWpf99qz9zhTXZ82neWFbQor8oTKHpiBiLaCQ4yEuGFUpCSETgkYx6B67tpaCDsSEx7dV1eh",
            "pub_key": "02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa",
            "priv_key": "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
            "chain_code": "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub68bdqB6Rafa5Y6ZFpvYY6cTqFRsac5rKXBDLftVSXmzehZnQD76UiZjPFMS7d2hriw5abC79Wz7EmoNTxsYo3o6vbpKP4M6uANVfNXYvGFT",
                "ex_priv": "xprv9ucHRfZXkJ1nKcUniu1XjUX6hQ36Cd8U9xHjsW5pySTfpmTFfZnEAmQuQ4vCSoChGYhBJnD2v7t1joVKiBkPuaAiusUxo84jLifUkipmXZo",
                "pub_key": "039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc",
                "priv_key": "d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e",
                "chain_code": "84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a",
                "parent_fprint": "607f628f",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6ArugY7cWqFZdqXDcoCEPY6dLCFDijyxkHhyjsAsJZpVHxTAqurwmEPK6yias9BZ48epVGA4c8zL8HsWVj5B4UGrVvuWQ17kPayfWLVYzax",
                "ex_priv": "xprv9wsZH2aigThGRMSkWmfE2Q9tnAQjKHG7P4nNwUmFkEHWRA82JNYhDS4qFhwkb62hQ9LU2MzMdsxAegwoDDhG7w3ZHjkhqJXXuvw6qmCbPyA",
                "pub_key": "02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76",
                "priv_key": "96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9",
                "chain_code": "f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6",
                "parent_fprint": "946d2a54",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6Bu41pMMxsFe8oNKMmUQyVJrP8LXFq6EiAK8HB4EZhxV5fsjbE4GesEpHVuAUP2Diy7h2EroQULLrk9iDKZRqaLzvWNJkZ3udasWSTERppf",
                "ex_priv": "xprv9xuhcJpU8VhLvKHrFjwQcMN7q6W2rNNPLwPXUned1NRWCsYb3gk274vLSCmbW4tsDHu2rh7cevEkDVeRZZqodJeKSNwMGV7AgDqqEk5MUsV",
                "pub_key": "03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64",
                "priv_key": "974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc",
                "chain_code": "7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b",
                "parent_fprint": "218182d8",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6Ecbt5Q9tpLC8YQ6q2ztm7ewLc4RjTsUYFVRMCTf5yr6Jsf8mXNoK15TUEia6ifNA2CfJZ21SiHDVaP1HsyWEBehzsFH7FdTVsbzg8wYEpf",
                "ex_priv": "xprvA1dFUZsG4Smtv4Kdj1TtPyiCnaDwL19dB2ZpYp43XeK7S5KzDz4YmCkycwrVjBTTE1BhbBgNQffmTxjZKecVH3Vd4iuTRvDDVDmNWKwGdUd",
                "pub_key": "03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933",
                "priv_key": "da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63",
                "chain_code": "5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a",
                "parent_fprint": "931223e4",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6GWju1NENdTYDcy8wDgZeiMqkVc3QCsiMFUqz3MMR7gD2SwXiFk4tt5ShtT8GYfx3MZhYsP4XJ3ZiNfTUiu9WrLtdMym2u8uJZxf45wGeoh",
                "ex_priv": "xprvA3XPVVqLYFuF18tfqC9ZHaR7CTmYzk9rz2ZFBewjrn9E9ecPAiRpM5kxrejBZAfBQ8aVxSYbtpJjtThnZqQC5BMqB6p93ZZt5kVyeXqnxDK",
                "pub_key": "020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f",
                "priv_key": "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67",
                "chain_code": "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7",
                "parent_fprint": "956c4629",
            },
        ],
    },
]

# Tests for public derivation from extended key
TEST_VECT_PUBLIC_DER_EX_KEY = {
    "ex_pub": "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCj9y9h81sHM8wE3eA95FyBBSyDvmMjrEFxY31T6toXzf6MoTfkHf",
    "ex_priv": "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "ex_pub": "xpub68WfVQ4Qr4Ys28v6SBmQCLSLho1h4bCKcWmiyGZ995yWjhAXJbRdDirnHDHQdhMmBszyaMEtADo7PSTCHRZziQeQb81S9Ki37SRUFsy31kR",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6Ab1s9PLra3aNauPfDeCJVMATTQrshof5ZkoWR54C26zUpLsgKTzdHYsUGAj5ThYfAyGNmtMU9KbpKTpjJXrPoBWmnKZznPfkb3a5SqoYdv",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Tests for public derivation from public key
TEST_VECT_PUBLIC_DER_PUB_KEY = {
    "pub_key": "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
    "priv_key": "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "pub_key": "02f29b81eaf45bff0aea79f37e0dd8148c7bff960574a8523802338bb4807d8b0f",
        },
        # m/0/0
        {
            "index": 0,
            "pub_key": "02bf9e5d584407a377d3a3bee3c2d4c29a73b943cd20cd5f436177fdaa92773ff6",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Test for seed that results in an invalid private key
TEST_RETRY_SEED = {
    "seed": "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
    "pub_key": "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20",
    "priv_key": "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
    "chain_code": "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
    "parent_fprint": "00000000",
}


#
# Tests
#
class Bip32Slip10Nist256p1Tests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(Bip32Slip10Nist256p1.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(Bip32Slip10Nist256p1, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(Bip32Slip10Nist256p1, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(Bip32Slip10Nist256p1, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(Bip32Slip10Nist256p1, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(Bip32Slip10Nist256p1, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(Bip32Slip10Nist256p1, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        self._test_public_derivation_ex_key(Bip32Slip10Nist256p1, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        self._test_public_derivation_pub_key(Bip32Slip10Nist256p1, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(Bip32Slip10Nist256p1, EllipticCurveTypes.NIST256P1)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(Bip32Slip10Nist256p1, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(Bip32Slip10Nist256p1, b"\x00" * (Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN - 1))

    # Test retry seed
    def test_retry_seed(self):
        bip32_ctx = Bip32Slip10Nist256p1.FromSeed(binascii.unhexlify(TEST_RETRY_SEED["seed"]))

        self.assertEqual(TEST_RETRY_SEED["priv_key"], bip32_ctx.PrivateKey().Raw().ToHex())
        self.assertEqual(TEST_RETRY_SEED["pub_key"], bip32_ctx.PublicKey().RawCompressed().ToHex())
        self.assertEqual(TEST_RETRY_SEED["chain_code"], bip32_ctx.ChainCode().ToHex())
        self.assertEqual(TEST_RETRY_SEED["parent_fprint"], bip32_ctx.ParentFingerPrint().ToHex())

    # Test old class
    def test_old_cls(self):
        self.assertTrue(Bip32Nist256p1 is Bip32Slip10Nist256p1)
