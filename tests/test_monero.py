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
from bip_utils import (
    MoneroPublicKey, MoneroPrivateKey, MoneroKeyError, Monero, Ed25519MoneroPublicKey, Ed25519MoneroPrivateKey
)
from bip_utils.monero.monero import MoneroConst
from .test_ecc import (
    TEST_ED25519_PRIV_KEY, TEST_ED25519_BLAKE2B_PRIV_KEY, TEST_NIST256P1_PRIV_KEY, TEST_SECP256K1_PRIV_KEY, TEST_SR25519_PRIV_KEY,
    TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PUB_KEY, TEST_SR25519_PUB_KEY,
    TEST_VECT_ED25519_PUB_KEY_INVALID, TEST_VECT_ED25519_MONERO_PRIV_KEY_INVALID
)


# Some random private spend keys
# Verified with the official Monero wallet and: https://xmr.llcoins.net/addresstests.html
TEST_VECT = [
    {
        "seed": b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107",
        "priv_skey": "2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107",
        "priv_vkey": "14467d1b9bb8d1fcfb5b7ae08cc9994367e917efd7e08cf94f9882ffa0629e09",
        "pub_skey": "a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422",
        "pub_vkey": "dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5",
        "primary_address": "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5UhSCham",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5UhSCham",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "8ACSUFFHQPT5bm2wok3B7W2LMC66SEA14NB5nLo6ZQbucr2iFPaBTyCQMkJoWi6vDnjYTWvot71evNc9USzMHjBW1FPRq2k",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "853mecUvFaKCZDTSmeY3S2SatQEVcEc57jTr15HjdoVF4rPdaSebydLYnwrkn9fn5rcJUQnS8c7WqfTotxwBRLpXJip2gzJ",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "85rtDvTdrMsR9CXjL4XCAEgEiwuXW3iP9SYevQskNVTydzamE7RAbVYKL5mHVbKsx3ExhLs5EvFn6Q9wfj55vEtt95fYVNv",
            },
        ]
    },
    {
        "seed": b"b6514a29ff612189af1bba250606bb5b1e7846fe8f31a91fc0beb393cddb6101",
        "priv_skey": "b6514a29ff612189af1bba250606bb5b1e7846fe8f31a91fc0beb393cddb6101",
        "priv_vkey": "8f3461d947f48cebd597dade700b6f345be43af8139b85fef7d577007462b509",
        "pub_skey": "323abccb6e92ee89b1a07f6829ab3e16cc4fd276377c11d84a5719808f16ec83",
        "pub_vkey": "4842482c21c0d0459f04dd7a27256b1743fe018727bd395c964a5ae9e3c6f6c1",
        "primary_address": "43XWXXDCyHwQ2oZtBc8LUm4pAs5koPg2kdBHgwQNJBKRNxbwRnYufB5CeQvnbkGiWE4thv1A7GptxGVDDPN4d8ehNpQv99J",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "43XWXXDCyHwQ2oZtBc8LUm4pAs5koPg2kdBHgwQNJBKRNxbwRnYufB5CeQvnbkGiWE4thv1A7GptxGVDDPN4d8ehNpQv99J",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "87QhdsHjCjMdWax6htvM7P2jFP9JAVC2eUpFiVdewQSpPbg1M4WPVCdHvvxH18WgyDTkfQVCNQ8j23oBhJYoBEQiF8onTRb",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "82tUn7VxgpfYdsjn8PygwLf8PyvinAGoEZxVG98d1FEsVVqUsWkJBL92NMUJ28hkGDdsZNCdcPH7McwSDxKYQ2UX1sHnDqD",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "87XnCr9zqmpbkkydpbafUtbRbRrCwTRfKD9hRs387BCF4aFqJ9d3wRiEzstySVgcMuio513aEpgxKMQtyvy1HaHSUbb18ad",
            },
        ]
    },
    {
        "seed": b"b8083b02224454c8671868930d0ae9e1aa347373ec450aaff336478ae32cc10d",
        "priv_skey": "b8083b02224454c8671868930d0ae9e1aa347373ec450aaff336478ae32cc10d",
        "priv_vkey": "b10e56f46ac431cc7b8374abe8eb569a30432a8738587416705514460b1f9e0b",
        "pub_skey": "310e380533336d850081ee63cece4a9ec6df17db97d67b18f35b4d5b406a2375",
        "pub_vkey": "51fa5e598f6aeb4516aa34e8dc974961cb0a7ef5398f6d329afd69ca2a8045bb",
        "primary_address": "43UvsrFvMbaPFHaZ5G57SyTZLPSKEZbQn5B42ZtErUGSLd9tEAVjSCzCZFEHopF7qrHMiX88Krpkk9TwHtZ31uTrNBNADjb",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "43UvsrFvMbaPFHaZ5G57SyTZLPSKEZbQn5B42ZtErUGSLd9tEAVjSCzCZFEHopF7qrHMiX88Krpkk9TwHtZ31uTrNBNADjb",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "85UDGmQ5SzVJ4gh78Q9DTzasCe1x7PA1JL3SYJeNverqfMiebxdB1MVaPVJ1BhSUwcVxU1vmjxeFx26xvz2akLinPh2c6Qk",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "82iPzGQVviR6vN1Zz46wKDMfRbowhwPyNYeaS4YMrfmUXUc2b5WkrSEND8oHYQY7dRiDZDcF3QaFaX8FkFJ9ETTi9Kt1eWg",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "8AAqYJnikUk87KEoyBd79jgVk2qS9fsxfEWcjrXPzSJVhjde3pFhMkW6SCbbd396L3NSJWhw1dGVe43G8V3iq2jrTKMqyCu",
            },
        ]
    },
    {
        "seed": b"373d5f961ec5e26982bd08d7b9d19633",
        "priv_skey": "1e0ecb4b35a5485194beb301df4bea5ad0cb411c9d3adca9338b4286d6ecc903",
        "priv_vkey": "64221cae902089ae247e24509865cd3e45a1c70f1c030587a709a5414d5c0603",
        "pub_skey": "3d8d37ef9b2293024073937463ef3f51009e4fe7be55d33f5b0052b14222314b",
        "pub_vkey": "416f39456d631c2969cf3db8ffde66d33344187e32ab994a2d542538530f8af2",
        "primary_address": "43xPtLXf1621Nr1LRDTacWEYpqxoekcV8BbdPmPMdnnCDb5GfWeWyFR7vm9E5ohGe9cKucMULKsF6DQcQZDLMUG9UQ1irHM",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "43xPtLXf1621Nr1LRDTacWEYpqxoekcV8BbdPmPMdnnCDb5GfWeWyFR7vm9E5ohGe9cKucMULKsF6DQcQZDLMUG9UQ1irHM",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "89ypkxkNvFVd2eiTSp3nBSKyH5AT4v27ZhUEt1A8di5pQTyk1XZQ3jmcMEHamv1B5mXYajJKrTkcVCxzqKJNoFAuKLh9YX6",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "89EpC5JZPG8JwT2seMLriUgAVCFe3jrSACbnNptBL1Q1CFhxKSSH6vNhuW5Ze75BRXStQPK71ghbw51xLQho1hnAKA32DEr",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "82yrVGZRqK7GUfLNuzcPAvdjUPUii7JU4J7hxE5sri1qSC9MNoRTt6xibZWaGvEEYCBEyDzeGK8jdMQBWr1Umz89B2PuGrz",
            },
        ]
    },
    {
        "seed": b"52ec255a434c3c7b0e3d0357084158e2",
        "priv_skey": "83bb85465f189b9328c8cadf0c75260500fbcc9ccd0c5b8d3783934741a9720d",
        "priv_vkey": "b42c6e744db8c45d1320ba28f79d0a1813b1821358fbf195958de4e19b23aa0b",
        "pub_skey": "aa4e7c95a40fc97b98c4801bee5347842ff0740368cfe0ffcba65ad4270dc45b",
        "pub_vkey": "8af4a1601edb665007c9e53cdf697e928c208fc2935c5aec6d3c0ff9c12dc2a6",
        "primary_address": "485S2N68Hw6Mg3WbxzsTXLP7PAAJVEqXmjnY8wEPhwQwGK5dQ46sdW5EPPw1sqnJbXRWhCX9zdcKjgYdqa7WMAGhKoBhm5U",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "485S2N68Hw6Mg3WbxzsTXLP7PAAJVEqXmjnY8wEPhwQwGK5dQ46sdW5EPPw1sqnJbXRWhCX9zdcKjgYdqa7WMAGhKoBhm5U",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "87ckP8eEKQuEt8uqQFWfrfUJEbsYr5KKZ4ntSzUnEUVoAf5wnBGmTnHQ4Z9RedYKKhamb4nSUqb8uFJpG7SZ8WqwMML2mH3",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "82pW4oNHx8qHcAKHH9yKCEjeWr7pckkbJG2AhEoiG2xzBRp11yWK4woQ3W4AXUviBPeUvz9ps2SqsWQcXEWdmmRtDq7ecj6",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "839pu7xJsZpaKN8HQ1S1btdNahvdxYGfP4HDSkT8QmYq2ged3vuTXFM9fVSEuVkXSdajoQ3v8qe13GXe2D7JoBQsEZyWg2q",
            },
        ]
    },
    {
        "seed": b"3aaba6a0c83ad6127dfb14a469c92afb",
        "priv_skey": "5288063e394817d6d3f811ae01d1e144b2c6e099ecc2bb908cafaf9cf46de908",
        "priv_vkey": "f4d4ee4630f874cb3b8a7cc630c0ac415b05204119809d59eeb8177b7096d90f",
        "pub_skey": "d1a7da825fcf942f42e5b8669375888d27f58360c7ab10a00e820ddc1030ce8e",
        "pub_vkey": "200c4944454c440b4b87e1581e7ccffe42c0068b415f39abfa75954ffa451133",
        "primary_address": "49ZvGRse9Ky8uVemEbKhLBQcPfxkRrbeXTmkWic1iZrmQmnxUL9Rbr32taQrh25jZxjXeZscqKb28VmQX4hLiQ3A6oq7HQs",
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "49ZvGRse9Ky8uVemEbKhLBQcPfxkRrbeXTmkWic1iZrmQmnxUL9Rbr32taQrh25jZxjXeZscqKb28VmQX4hLiQ3A6oq7HQs",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "8BVqbTDCaG54Xwpo52D8PX1WhjpaudXUSE7VkWUNRJFhZE8FC9PKM29SQV3bPxv17aFx9DvGSgan6DJLp8g3JYgMR2piiFG",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "88X5TTo49bzQHeW2EmjSqp1gtZoPdCWRoMwD5Z8CL8f2KFoxtbZewS2TYNpaXPdEtUZURyjJergEXgwKzSADQytMKY9uw2H",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "84ZSM6FweBLgHuJRi3ZhFxFYLKbfHUPnfaejFkmSCoPs9kxoNZoryMNCT37h8YM2X9DRo8Q5Rm3hRDKhf7mV4JtyK7JQF1h",
            },
        ]
    },
]

# Generic seed for testing
TEST_SEED = b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874107"


#
# Tests
#
class MoneroTests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction
    def test_vector_from_seed(self):
        for test in TEST_VECT:
            monero = Monero.FromSeed(binascii.unhexlify(test["seed"]))
            self.__test_keys_and_addresses(monero, test, False)

    # Run all tests in test vector using FromPrivateSpendKey for construction
    def test_vector_from_priv_key(self):
        for test in TEST_VECT:
            priv_skey_bytes = binascii.unhexlify(test["priv_skey"])

            # Test from bytes
            monero = Monero.FromPrivateSpendKey(priv_skey_bytes)
            self.__test_keys_and_addresses(monero, test, False)
            # Test from key object
            monero = Monero.FromPrivateSpendKey(Ed25519MoneroPrivateKey(priv_skey_bytes))
            self.__test_keys_and_addresses(monero, test, False)

    # Run all tests in test vector using FromWatchOnly for construction
    def test_vector_from_watch_only(self):
        for test in TEST_VECT:
            priv_vkey_bytes = binascii.unhexlify(test["priv_vkey"])
            pub_skey_bytes = binascii.unhexlify(test["pub_skey"])

            # Test from bytes
            monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes)
            self.__test_keys_and_addresses(monero, test, True)
            # Test from key object
            monero = Monero.FromWatchOnly(Ed25519MoneroPrivateKey(priv_vkey_bytes),
                                          Ed25519MoneroPublicKey(pub_skey_bytes))
            self.__test_keys_and_addresses(monero, test, True)


    # Test invalid subaddress indexes
    def test_invalid_subaddress_idx(self):
        monero = Monero.FromSeed(binascii.unhexlify(TEST_SEED))

        self.assertRaises(ValueError, monero.SubAddress, -1, 0)
        self.assertRaises(ValueError, monero.SubAddress, 0, -1)
        self.assertRaises(ValueError, monero.SubAddress, MoneroConst.SUBADDR_MAX_IDX + 1, 0)
        self.assertRaises(ValueError, monero.SubAddress, 0, MoneroConst.SUBADDR_MAX_IDX + 1)

    # Test invalid parameters
    def test_invalid_params(self):
        # Invalid types
        self.assertRaises(TypeError, MoneroPrivateKey, TEST_ED25519_PRIV_KEY)
        self.assertRaises(TypeError, MoneroPrivateKey, TEST_ED25519_BLAKE2B_PRIV_KEY)
        self.assertRaises(TypeError, MoneroPrivateKey, TEST_NIST256P1_PRIV_KEY)
        self.assertRaises(TypeError, MoneroPrivateKey, TEST_SECP256K1_PRIV_KEY)
        self.assertRaises(TypeError, MoneroPrivateKey, TEST_SR25519_PRIV_KEY)

        self.assertRaises(TypeError, MoneroPublicKey, TEST_ED25519_PUB_KEY)
        self.assertRaises(TypeError, MoneroPublicKey, TEST_ED25519_BLAKE2B_PUB_KEY)
        self.assertRaises(TypeError, MoneroPublicKey, TEST_NIST256P1_PUB_KEY)
        self.assertRaises(TypeError, MoneroPublicKey, TEST_SECP256K1_PUB_KEY)
        self.assertRaises(TypeError, MoneroPublicKey, TEST_SR25519_PUB_KEY)

        # Invalid keys
        for test in TEST_VECT_ED25519_PUB_KEY_INVALID:
            self.assertRaises(MoneroKeyError, MoneroPublicKey.FromBytes, binascii.unhexlify(test))
        for test in TEST_VECT_ED25519_MONERO_PRIV_KEY_INVALID:
            self.assertRaises(MoneroKeyError, MoneroPrivateKey.FromBytes, binascii.unhexlify(test))

    # Test keys and addresses
    def __test_keys_and_addresses(self, monero, test, is_watch_only):
        # Test watch-only flag
        self.assertEqual(monero.IsWatchOnly(), is_watch_only)

        # Test key objects
        if not is_watch_only:
            self.assertTrue(isinstance(monero.PrivateSpendKey().KeyObject(), Ed25519MoneroPrivateKey))
        self.assertTrue(isinstance(monero.PrivateViewKey().KeyObject(), Ed25519MoneroPrivateKey))
        self.assertTrue(isinstance(monero.PublicSpendKey().KeyObject(), Ed25519MoneroPublicKey))
        self.assertTrue(isinstance(monero.PublicViewKey().KeyObject(), Ed25519MoneroPublicKey))

        # Test keys
        if not is_watch_only:
            self.assertEqual(test["priv_skey"], monero.PrivateSpendKey().Raw().ToHex())
            self.assertEqual(test["priv_skey"], str(monero.PrivateSpendKey().Raw()))
            self.assertEqual(test["priv_vkey"], monero.PrivateViewKey().Raw().ToHex())
            self.assertEqual(test["priv_vkey"], str(monero.PrivateViewKey().Raw()))
        else:
            self.assertRaises(MoneroKeyError, monero.PrivateSpendKey)

        self.assertEqual(test["pub_skey"], monero.PublicSpendKey().RawCompressed().ToHex())
        self.assertEqual(test["pub_skey"], str(monero.PublicSpendKey().RawCompressed()))
        self.assertEqual(test["pub_skey"], monero.PublicSpendKey().RawUncompressed().ToHex())
        self.assertEqual(test["pub_skey"], str(monero.PublicSpendKey().RawUncompressed()))

        self.assertEqual(test["pub_vkey"], monero.PublicViewKey().RawCompressed().ToHex())
        self.assertEqual(test["pub_vkey"], str(monero.PublicViewKey().RawCompressed()))
        self.assertEqual(test["pub_vkey"], monero.PublicViewKey().RawUncompressed().ToHex())
        self.assertEqual(test["pub_vkey"], str(monero.PublicViewKey().RawUncompressed()))

        # Test primary address
        self.assertEqual(test["primary_address"], monero.PrimaryAddress())

        # Test subaddresses
        for test_subaddr in test["subaddresses"]:
            subaddr = monero.SubAddress(test_subaddr["minor_idx"], test_subaddr["major_idx"])
            self.assertEqual(test_subaddr["address"], subaddr)
