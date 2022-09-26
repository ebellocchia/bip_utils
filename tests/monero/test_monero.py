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
    Ed25519MoneroPrivateKey, Ed25519MoneroPublicKey, Monero, MoneroCoins, MoneroKeyError, MoneroPrivateKey,
    MoneroPublicKey
)
from bip_utils.monero.conf import MoneroCoinConf
from bip_utils.monero.monero_subaddr import MoneroSubaddressConst


# Some random private spend keys
# Verified with the official Monero wallet and: https://xmr.llcoins.net/addresstests.html
TEST_VECT = [
    # Main net
    {
        "seed": b"2c9623882df4940a734b009e0732ce5a8de7a62c4c1a2a53767a8f6c04874117",
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "3fc22d2b139182b29cae08fb2838ef458de7a62c4c1a2a53767a8f6c04874107",
        "priv_vkey": "66e7495a49d2f1b9458204386bd6aadf6402c270d37d503a1cebde58a0d38a00",
        "pub_skey": "f7ee64693c501c0f6112f5ab4d33b405c35f66efb2c704ffbd2f7dc63408235e",
        "pub_vkey": "7f9e54e6dc3fbbd4b7a3b4412c22f4e2d78ee91ddfeaa30a9181e4b374ac3613",
        "primary_address": "4B23epeYLCj3aCTG8X83ZM1xunHBjWEB5jmzM1zfrAKcGokjBPvS7eAcadEQZEgDhDeweod9KEZ5L2mXYVthxdxy3CQiRDK",
        "integrated_address": {
            "payment_id": b"d6f093554c0daa94",
            "address": "4LiifdU2wUF3aCTG8X83ZM1xunHBjWEB5jmzM1zfrAKcGokjBPvS7eAcadEQZEgDhDeweod9KEZ5L2mXYVthxdxy4KUCty2MEBbHiGc8eM",
        },
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "4B23epeYLCj3aCTG8X83ZM1xunHBjWEB5jmzM1zfrAKcGokjBPvS7eAcadEQZEgDhDeweod9KEZ5L2mXYVthxdxy3CQiRDK",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "89EpSrB4wKB3UrLk8Zf4dHhvcfo1TqVfR6PAE8WPtwK9YuJhiEaU49y8w9fBaCTPUSCmaYTQbD3LhgbkHriuQLgDMM1dpsk",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "87zT4PHnBDUJodyx5gzbenceaByre9ijiHa9FkZnu2yJP2xLEv9ivMTcLtkzaFp6pffWwcZ2htGU94VGiXMsR67q9yenKYT",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "88gNnRiJ4q9BrcsaxoTxFMPeVHPuZELNwTZgqSNwbRKv9gSbfzJDgyKB1sKsH81mGVN991LaAaN9f5v8orhk6Yf64F2XmT8",
            },
        ]
    },
    {
        "seed": b"b6514a29ff612189af1bba250606bb5b1e7846fe8f31a91fc0beb393cddb6101",
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "b6514a29ff612189af1bba250606bb5b1e7846fe8f31a91fc0beb393cddb6101",
        "priv_vkey": "8f3461d947f48cebd597dade700b6f345be43af8139b85fef7d577007462b509",
        "pub_skey": "323abccb6e92ee89b1a07f6829ab3e16cc4fd276377c11d84a5719808f16ec83",
        "pub_vkey": "4842482c21c0d0459f04dd7a27256b1743fe018727bd395c964a5ae9e3c6f6c1",
        "primary_address": "43XWXXDCyHwQ2oZtBc8LUm4pAs5koPg2kdBHgwQNJBKRNxbwRnYufB5CeQvnbkGiWE4thv1A7GptxGVDDPN4d8ehNpQv99J",
        "integrated_address": {
            "payment_id": b"ccc172c2ffcac9d8",
            "address": "4DEBYL2haZTQ2oZtBc8LUm4pAs5koPg2kdBHgwQNJBKRNxbwRnYufB5CeQvnbkGiWE4thv1A7GptxGVDDPN4d8ehZR6s3aQNNzLRREzGFz",
        },
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
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "b8083b02224454c8671868930d0ae9e1aa347373ec450aaff336478ae32cc10d",
        "priv_vkey": "b10e56f46ac431cc7b8374abe8eb569a30432a8738587416705514460b1f9e0b",
        "pub_skey": "310e380533336d850081ee63cece4a9ec6df17db97d67b18f35b4d5b406a2375",
        "pub_vkey": "51fa5e598f6aeb4516aa34e8dc974961cb0a7ef5398f6d329afd69ca2a8045bb",
        "primary_address": "43UvsrFvMbaPFHaZ5G57SyTZLPSKEZbQn5B42ZtErUGSLd9tEAVjSCzCZFEHopF7qrHMiX88Krpkk9TwHtZ31uTrNBNADjb",
        "integrated_address": {
            "payment_id": b"6e8b9ea55f3e01af",
            "address": "4DBbtf5Qxs6PFHaZ5G57SyTZLPSKEZbQn5B42ZtErUGSLd9tEAVjSCzCZFEHopF7qrHMiX88Krpkk9TwHtZ31uTrYMKkzEB2yoELnsszjL",
        },
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
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "1e0ecb4b35a5485194beb301df4bea5ad0cb411c9d3adca9338b4286d6ecc903",
        "priv_vkey": "64221cae902089ae247e24509865cd3e45a1c70f1c030587a709a5414d5c0603",
        "pub_skey": "3d8d37ef9b2293024073937463ef3f51009e4fe7be55d33f5b0052b14222314b",
        "pub_vkey": "416f39456d631c2969cf3db8ffde66d33344187e32ab994a2d542538530f8af2",
        "primary_address": "43xPtLXf1621Nr1LRDTacWEYpqxoekcV8BbdPmPMdnnCDb5GfWeWyFR7vm9E5ohGe9cKucMULKsF6DQcQZDLMUG9UQ1irHM",
        "integrated_address": {
            "payment_id": b"0c0226208617eacd",
            "address": "4Df4u9M9cMY1Nr1LRDTacWEYpqxoekcV8BbdPmPMdnnCDb5GfWeWyFR7vm9E5ohGe9cKucMULKsF6DQcQZDLMUG9hVABCrkrKS1QD1aF8A",
        },
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
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "83bb85465f189b9328c8cadf0c75260500fbcc9ccd0c5b8d3783934741a9720d",
        "priv_vkey": "b42c6e744db8c45d1320ba28f79d0a1813b1821358fbf195958de4e19b23aa0b",
        "pub_skey": "aa4e7c95a40fc97b98c4801bee5347842ff0740368cfe0ffcba65ad4270dc45b",
        "pub_vkey": "8af4a1601edb665007c9e53cdf697e928c208fc2935c5aec6d3c0ff9c12dc2a6",
        "primary_address": "485S2N68Hw6Mg3WbxzsTXLP7PAAJVEqXmjnY8wEPhwQwGK5dQ46sdW5EPPw1sqnJbXRWhCX9zdcKjgYdqa7WMAGhKoBhm5U",
        "integrated_address": {
            "payment_id": b"63c84b79ab434598",
            "address": "4Hn73AucuCcMg3WbxzsTXLP7PAAJVEqXmjnY8wEPhwQwGK5dQ46sdW5EPPw1sqnJbXRWhCX9zdcKjgYdqa7WMAGhUqByd94QKTJJ9vmXwN",
        },
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
        "coin": MoneroCoins.MONERO_MAINNET,
        "priv_skey": "5288063e394817d6d3f811ae01d1e144b2c6e099ecc2bb908cafaf9cf46de908",
        "priv_vkey": "f4d4ee4630f874cb3b8a7cc630c0ac415b05204119809d59eeb8177b7096d90f",
        "pub_skey": "d1a7da825fcf942f42e5b8669375888d27f58360c7ab10a00e820ddc1030ce8e",
        "pub_vkey": "200c4944454c440b4b87e1581e7ccffe42c0068b415f39abfa75954ffa451133",
        "integrated_address": {
            "payment_id": b"07c438e423452c60",
            "address": "4KGbHEh8kbV8uVemEbKhLBQcPfxkRrbeXTmkWic1iZrmQmnxUL9Rbr32taQrh25jZxjXeZscqKb28VmQX4hLiQ3A9Y4NncT7LZHBt9N68a",
        },
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
    # Stage net
    {
        "seed": b"b4d9eab56043b1f0ac82affae32cd58049536d2289ec948502076961ae7da50e",
        "coin": MoneroCoins.MONERO_STAGENET,
        "priv_skey": "b4d9eab56043b1f0ac82affae32cd58049536d2289ec948502076961ae7da50e",
        "priv_vkey": "b9c02bf2e8e30169cbbe2c22135a65e02cb80531f7bed1105f562cc61ce10b07",
        "pub_skey": "ee3f0bbbd4ee4d30d05db97b0e28dfa1c624f436f886488fd6014a74a9c47edd",
        "pub_vkey": "c30355010a0083776b37b32457d4f654fb956e1be535fc78871e170cb3d8a58e",
        "primary_address": "5Aro6RZf2gc9AZGHkyVLkvU4Qonc8yQ8fR4PZTy9haCVe6NHSMH4TtNLyWhovaP75PFDSUC9cAML7MAGhXS56o16H7BmpEP",
        "integrated_address": {
            "payment_id": b"b11e1adb1b805574",
            "address": "5LZU7EP9dx89AZGHkyVLkvU4Qonc8yQ8fR4PZTy9haCVe6NHSMH4TtNLyWhovaP75PFDSUC9cAML7MAGhXS56o16QsHp2B9FRB2E9gyPSR",
        },
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "5Aro6RZf2gc9AZGHkyVLkvU4Qonc8yQ8fR4PZTy9haCVe6NHSMH4TtNLyWhovaP75PFDSUC9cAML7MAGhXS56o16H7BmpEP",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "74oX2Dpt1g53S1AUVmcitNMaatEtSw4P79gi4Dnk8dYH7BAS9PFbcrQA27WWLurvzR9hL87soCikrb8oNvuW7bL8K2YVwh5",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "7BKMWuYs9JTbFsjQzDA2aB4orcscsgUY2ZyWVKpRCbZwVNBCjwpyFSqQDYp7mHE4oGRQDWJwj1KFJeEK1mF4397a8swKjK8",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "75VAUvDcD6mfSt61BgEhh7QxH3FxC1LoAawp3fM9nL4eS6a3ZXPzjq9j2fojYsurn4PtPBRJfnhg1J1NFnupHEyZLLbbKJC",
            },
        ]
    },
    {
        "seed": b"d928df59e92de9536d138dcb13c2aec277b23a68ad744fddb1991706df3fe40e",
        "coin": MoneroCoins.MONERO_STAGENET,
        "priv_skey": "d928df59e92de9536d138dcb13c2aec277b23a68ad744fddb1991706df3fe40e",
        "priv_vkey": "261ac9d48ed740ca6ae85e9562246f895fca5be04bc2c75e93f81d5ae40b5708",
        "pub_skey": "7a9a82b3a466eb41e0463397e3e58c9111d480116c3f289c0db6c8870cf1d777",
        "pub_vkey": "d583c6ae118d21fb56d60e43d76cd2d262d490ebe2f2722a616b26b1c5165d6d",
        "primary_address": "56UcuBCz4EvC25fW1TqFKZRGMj1LkrRCKT6v5SSnJyaeM3YLdSV85tCj3JhQtKSr2DcC1UsD8DdCM869NZ6itcUkDPAaTQq",
        "integrated_address": {
            "payment_id": b"27d3bf2d7c0a8513",
            "address": "5GBHuz2UfWSC25fW1TqFKZRGMj1LkrRCKT6v5SSnJyaeM3YLdSV85tCj3JhQtKSr2DcC1UsD8DdCM869NZ6itcUkKFwrhfdHSzQ3FaqMLV",
        },
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "56UcuBCz4EvC25fW1TqFKZRGMj1LkrRCKT6v5SSnJyaeM3YLdSV85tCj3JhQtKSr2DcC1UsD8DdCM869NZ6itcUkDPAaTQq",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "73MsDNhZ51MdWRgAk258ExUbhJUkyrkWY6kYHAF7cjrr57LwtzqPbhUKuL5rHYYFBdBCvobvoqZP3V3CMkFDuvrP9XQDS3f",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "77S3nd9BZBn9zXLWBQ8WBK1oK326obn6QQTkjLFV8wVjDouuQKzmjeQ9qQdDU5idoGJt13wshd9xkFUNMph6o27jFfYhvwU",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "74GVf2NiLobj8RbHvDzdv2cNVi8UGQ7T9bd22yJDoALpRwzLPDb5ha3eZ4W5ABXZ5ELuG6ichauw2CNZfZBtXZYeSthRo2y",
            },
        ]
    },
    # Test net
    {
        "seed": b"a52d32df742c7ecf639be062ef4cd3d726117645542693fbfc44f5a186724307",
        "coin": MoneroCoins.MONERO_TESTNET,
        "priv_skey": "a52d32df742c7ecf639be062ef4cd3d726117645542693fbfc44f5a186724307",
        "priv_vkey": "5a07cb9f334ee0f28078f1dea3b554e8747db04b3e628b61f59fc4e455785f07",
        "pub_skey": "bff6481aeee5a0cf2949bee430888797b18af5542828ef5377d2d5e457d96235",
        "pub_vkey": "e81c525c3627f24a322466b4a0c704f58952271dbd115f972d6bf7d1b927a40b",
        "primary_address": "9zSaACcBx3HbeizJiyvY5USNcoMNtPiQvExkCKzBGJQqA1xpKhWGjDjDQnzBbubxx3i51d9mZCNvrSHcQVRUAK3H2HmhC9w",
        "integrated_address": {
            "payment_id": b"c39fd3c0f1edeab6",
            "address": "AA9FB1RgZJobeizJiyvY5USNcoMNtPiQvExkCKzBGJQqA1xpKhWGjDjDQnzBbubxx3i51d9mZCNvrSHcQVRUAK3H2y8NSmq3dB7MZNsYJB",
        },
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "9zSaACcBx3HbeizJiyvY5USNcoMNtPiQvExkCKzBGJQqA1xpKhWGjDjDQnzBbubxx3i51d9mZCNvrSHcQVRUAK3H2HmhC9w",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "BgZvFFW75akXq6MUHv67NEaFoHoC1F8LM9djSm6akiV6azL1nv6xh949NwQQZYM438cBUWWjFHaUjSpgA9MtUhNdBZC4Mvw",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "BbwepBiPBYUjCb6tF9d3a4Xi9y9FGgUMvEUh3hJcxqDBFNjmtHULoTiBzGHK9q6y3ZC7pzCUtNP9ueqmNXpMk6reQnCHMd7",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "Bazi9dJJc9g4A4wmgGKFEGKUhEpTH2jeqhPccxDiR8qRE3BXAn5c3qMKxiJZVSBFNP5jiM1uyBj94B93msJZDFzG8GV8NQ4",
            },
        ]
    },
    {
        "seed": b"64f39a8746c4d8825944fb896ad5b962f040a8811f2050e7d9edc5a0f17aab0a",
        "coin": MoneroCoins.MONERO_TESTNET,
        "priv_skey": "64f39a8746c4d8825944fb896ad5b962f040a8811f2050e7d9edc5a0f17aab0a",
        "priv_vkey": "22097897de557cac380a5f6eed368364725bb9321ba67632cb776b9d4ca0c903",
        "pub_skey": "70d532772bf2656a27abf25b3f1cd16c6027b455cc81e69743aec8182731106f",
        "pub_vkey": "7a68fb0d7f4a046be96b5adc224a4c2f4ecf9879acc113e438cdba773a1278be",
        "primary_address": "9wSeitNRRdnJkqVqj7fFKvK8NzQVKUsyPSJTLLJNRgMVKeUiSsJ2Pb1K3t1upYkiiw8uwqWfcqa8ifB3DXhMEDEFNXkC44K",
        "integrated_address": {
            "payment_id": b"d7af025ab223b74e",
            "address": "A79KjhBv2uJJkqVqj7fFKvK8NzQVKUsyPSJTLLJNRgMVKeUiSsJ2Pb1K3t1upYkiiw8uwqWfcqa8ifB3DXhMEDEFYvQs7AYR2Hc9uc9ikY",
        },
        "subaddresses": [
            {
                "major_idx": 0,
                "minor_idx": 0,
                "address": "9wSeitNRRdnJkqVqj7fFKvK8NzQVKUsyPSJTLLJNRgMVKeUiSsJ2Pb1K3t1upYkiiw8uwqWfcqa8ifB3DXhMEDEFNXkC44K",
            },
            {
                "major_idx": 0,
                "minor_idx": 1,
                "address": "BcPG7CQd17mQ2J6hqWD59w7FqunPzJwhpCfyz6jzfzriaDnC7mHMhvZhqftw8w632ij2mpq8c1MsJPanrMQTKY547pTBvTq",
            },
            {
                "major_idx": 1,
                "minor_idx": 0,
                "address": "BYdWWX8N45gELret2WxTgKeGkwLLEAxGnFXLjStviAwaBng18qgXqzFDgvwdEsrjKbZAKKunaRGDNWZZiZD4EEczKmgN6K2",
            },
            {
                "major_idx": 1,
                "minor_idx": 1,
                "address": "BbT4WiU2QVQbSn5XFHwJzb88Wxbh8F7YAHiEJGYyNpeFgsfruboReEKdhyxRwjx9veAT3tBvNXfTwJmW7Q19zCS7LVPdM6S",
            },
        ]
    },
]

# Generic seed for testing
TEST_SEED = b"\x01" * Ed25519MoneroPrivateKey.Length()


#
# Tests
#
class MoneroTests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction
    def test_vector_from_seed(self):
        for test in TEST_VECT:
            monero = Monero.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])
            self.__test_monero_obj(monero, test, False)

    # Run all tests in test vector using FromPrivateSpendKey for construction
    def test_vector_from_priv_key(self):
        for test in TEST_VECT:
            priv_skey_bytes = binascii.unhexlify(test["priv_skey"])

            # Test from bytes
            monero = Monero.FromPrivateSpendKey(priv_skey_bytes, test["coin"])
            self.__test_monero_obj(monero, test, False)
            # Test from key object
            monero = Monero.FromPrivateSpendKey(Ed25519MoneroPrivateKey(priv_skey_bytes), test["coin"])
            self.__test_monero_obj(monero, test, False)

    # Run all tests in test vector using FromWatchOnly for construction
    def test_vector_from_watch_only(self):
        for test in TEST_VECT:
            priv_vkey_bytes = binascii.unhexlify(test["priv_vkey"])
            pub_skey_bytes = binascii.unhexlify(test["pub_skey"])

            # Test from bytes
            monero = Monero.FromWatchOnly(priv_vkey_bytes, pub_skey_bytes, test["coin"])
            self.__test_monero_obj(monero, test, True)
            # Test from key object
            monero = Monero.FromWatchOnly(Ed25519MoneroPrivateKey(priv_vkey_bytes),
                                          Ed25519MoneroPublicKey(pub_skey_bytes),
                                          test["coin"])
            self.__test_monero_obj(monero, test, True)

    # Test invalid subaddress indexes
    def test_invalid_subaddress_idx(self):
        monero = Monero.FromSeed(TEST_SEED)

        self.assertRaises(ValueError, monero.Subaddress, -1, 0)
        self.assertRaises(ValueError, monero.Subaddress, 0, -1)
        self.assertRaises(ValueError, monero.Subaddress, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1, 0)
        self.assertRaises(ValueError, monero.Subaddress, 0, MoneroSubaddressConst.SUBADDR_MAX_IDX + 1)

    # Test Monero object
    def __test_monero_obj(self, monero_obj, test, is_watch_only):
        # Test watch-only flag
        self.assertEqual(monero_obj.IsWatchOnly(), is_watch_only)
        self.assertTrue(isinstance(monero_obj.CoinConf(), MoneroCoinConf))

        # Test key objects
        if not is_watch_only:
            self.assertTrue(isinstance(monero_obj.PrivateSpendKey(), MoneroPrivateKey))
        self.assertTrue(isinstance(monero_obj.PrivateViewKey(), MoneroPrivateKey))
        self.assertTrue(isinstance(monero_obj.PublicSpendKey(), MoneroPublicKey))
        self.assertTrue(isinstance(monero_obj.PublicViewKey(), MoneroPublicKey))

        # Test keys
        if not is_watch_only:
            self.assertEqual(test["priv_skey"], monero_obj.PrivateSpendKey().Raw().ToHex())
            self.assertEqual(test["priv_vkey"], monero_obj.PrivateViewKey().Raw().ToHex())
        else:
            self.assertRaises(MoneroKeyError, monero_obj.PrivateSpendKey)

        self.assertEqual(test["pub_skey"], monero_obj.PublicSpendKey().RawCompressed().ToHex())
        self.assertEqual(test["pub_skey"], monero_obj.PublicSpendKey().RawUncompressed().ToHex())

        self.assertEqual(test["pub_vkey"], monero_obj.PublicViewKey().RawCompressed().ToHex())
        self.assertEqual(test["pub_vkey"], monero_obj.PublicViewKey().RawUncompressed().ToHex())

        # Test primary address
        self.assertEqual(test["primary_address"], monero_obj.PrimaryAddress())

        # Test integrated address
        payment_id = binascii.unhexlify(test["integrated_address"]["payment_id"])
        self.assertEqual(test["integrated_address"]["address"], monero_obj.IntegratedAddress(payment_id))

        # Test subaddresses
        for test_subaddr in test["subaddresses"]:
            subaddr = monero_obj.Subaddress(test_subaddr["minor_idx"], test_subaddr["major_idx"])
            self.assertEqual(test_subaddr["address"], subaddr)
