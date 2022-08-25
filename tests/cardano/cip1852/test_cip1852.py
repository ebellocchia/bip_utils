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
from bip_utils import Bip44Coins, Bip49Coins, Bip84Coins, Bip86Coins, Cip1852, Cip1852Coins
from tests.bip.bip44.test_bip44 import TEST_SEED
from tests.bip.bip44_base.test_bip44_base import Bip44BaseTests


# Test vector
TEST_VECT = [
    # Cardano main net (Icarus)
    {
        "coin": Cip1852Coins.CARDANO_ICARUS,
        "names": ("Cardano", "ADA"),
        "is_testnet": False,
        "seed": b"0000000000000000000000000000000000000000",
        "ex_master": "xprv3QESAWYc9vDdZetNwNFxZpyhKNtt4jWb2LuyRPfivjZoQN1U3HMCE9Uz5VAb2XhWiU1ByYMeCnjsdx3ptUZ8GHMx8uCABr7oGaKNsQmb4MHE1cXnhiwBwJLrbfvtGRsF1pnKx1hMypH7VngaDWcwhq5",
        "wif_master": "",
        "account": {
            "ex_pub": "xpub6DUARacQUBVjuzYbuJcCHrrBFZRPW77T9azYjcfVib74wQcrJLx5L6iAad5nG5Q31mqM7GqPeHC3oh5nFSvWjiYKsA68sS9WQL8KW71HizP",
            "ex_priv": "xprv3ST19gxjCZJ9V1B7nA9eTu8aE8R7EZWZv6BUSL75hhYuUMwrEwn3icxmLJz8YFpzhBUNGPjJLGxdxhryMefD1Duex8sNR6KzRBnJN66jTeiPEAKcohdauX95tmRXfMrtaPegqZKVUTZkabvNNwF6gDz",
        },
        "chain_ext": {
            "ex_pub": "xpub6EcciAquF76hSEE4uZhRduj3WLTdywuM3gnvnHWbnoqymhNyCN9Bjy3YVHed56waaVRkeUjKWSPm5nLt2iYy9FVpuUK4ZGwMXGxzz5SqgU5",
            "ex_priv": "xprv3Snk7VW1Q7eJwiecq9vsGK2vM1qZ3p1iTLw8t7XNnSSTa7MYPL1aTk8zZNVU9th9EbiA1FFkqpMPnwsZ5742Ati8ZbU6rZk9xoxmPV38Cotdn8bm9CxQZqJoWCtGEg4CNCqxdLTYCfTsJmLz5uQ9ivG",
        },
        "addresses": [
            "addr1qxz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969y7r3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0q8eqdws",
            "addr1qyg8whf7u4sjlw0fjapgyf6jzayx7svd9xqsv6thymk7s3kr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0quke8qu",
            "addr1q85q038lxyc2dftwxqt80fgxm49h2l8pya7s9cvrvx6478xr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qg9enpz",
            "addr1qxv9q3hkjjhel8vgvrgfl6fpfyax55wpctuwtqfa7veyj6kr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qzv6xmm",
            "addr1q8chn3ekmz9f44vkzywy93uujpg4pmpgsva7jgkvqf7ahrxr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qvrq90x",
        ],
        "staking_address": "stake1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8squng76",
    },
    # Cardano main net (Ledger)
    {
        "coin": Cip1852Coins.CARDANO_LEDGER,
        "names": ("Cardano", "ADA"),
        "is_testnet": False,
        "seed": b"0000000000000000000000000000000000000000",
        "ex_master": "xprv3QESAWYc9vDdZRFPSMtkAstjsSSrMBCQ5qzkY4SnjuTFDYsXivTP43U7PspSRKNBdHVt8j4xidQqKFgbyryQbk1yFyuNwgsj13MLNPoF9W6Vaceon1gULFGTzHg4v9hZx3kkpFM1wi9DrbgnVhEUwia",
        "wif_master": "",
        "account": {
            "ex_pub": "xpub6C81RzDgoVC6Wvshp14Jq1YaYqvfZ2srXFs6NkugRKXBHR88q84mB4bZjrh2nRcS1EXmExUdjEzf7JpaCMy3Lo3CJrABf8YnMJqahvmkWTJ",
            "ex_priv": "xprv3S3na3DSNqpBEAQz1QxjyGH5mwJHfzXYY7HPr8VdrDtXUjDDWtfpyb1qKZpPDXCVfLFrhkNgXGVbReWhq4MXF2AbfyGCBGB4DnSFAwDm7GUhVHcTw1321bEMC1ameCUhGg1x1WcHMRM3q34GizJ2deS",
        },
        "chain_ext": {
            "ex_pub": "xpub6DdUn7r4scAN5ajsQE65PgnRLL9TrNAzsYAzBWdHfYsg157PycbaZbu4yiD81oLRsEm2tEVw4JpT5PdcQ859cKDkJLDBpf5C2a3XbAxXbiB",
            "ex_priv": "xprv3SVmfmsNrjrPDB3qiWTpsvJR6bcu4JANiEEyAkZYaHa3uguRJBWGvzutJXbXvqiNvXfsdPRwhstFbcbyNnu2zdgZFwZBNeucnuSvJmNRn7uCJGvFF5kta6U3UyRH7fWqkECJA2BZnrFSRzDZKUtqm6G",
        },
        "addresses": [
            "addr1q9ug2zur0nmy0pwjk023cnzxlru6vc3rw67r9qlsufjg5rtsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksx5aka8",
            "addr1qx6yq2qe4cje59azajeg3eqzh79kglps5qq5xmx9pdu2mctsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksvyxuuh",
            "addr1qxrtelvca45kah8vszqpnurvcpdkwy9wfmph20eldu53wlmsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvukstdeypu",
            "addr1qxu62njn5uqnjuje09yakmzzxh35w8dh0z32aranp3qdm8msgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksp3qenn",
            "addr1q9tya3ymcmrtvty0gfr8qv9mwe4flytjydlsk6ju776583nsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuks6xxfg7",
        ],
        "staking_address": "stake1u9cypgkgzlknjktakdemm73p49k5rtyqznwra3p0h8rxwtg0vjunm",
    },

    # Cardano test net (Icarus)
    {
        "coin": Cip1852Coins.CARDANO_ICARUS_TESTNET,
        "names": ("Cardano TestNet", "ADA"),
        "is_testnet": True,
        "seed": b"0000000000000000000000000000000000000000",
        "ex_master": "GPvmpfpp1e1m4t8kXDrJMmbfFNDR4HSNYQwrsYNcct8NSry59MPXDJy3a8vyT8K1DFdRkK17yCYres9gZo3CUKoPzeb3huhsCMEHkRDZ7swM5sENyjtMMKGS5GQMSTaNpZSfPnpHxxVL9dKPnCoZErtzsNH",
        "wif_master": "",
        "account": {
            "ex_pub": "tpubDDqnwpS6BTTCBnjTMVbHVnBYagX3VVcWhDar6Aie4VrxghHZNZoAUYNzpfAZnaMGogNFirMGBP26VsaPeJmkd9zcvkqSYxojzHijG4rvAWA",
            "ex_priv": "GPvmpi3NzpRt7XDGSa93CZVM9SNHy2xbiEwqmHe7dpZjDpxBDMKuQyPu4cQkhx8Yiykuj2UJG3vWnMNStYrLwVuUjb8kX9P5RbSUu2gUcZGVVAfYCHgBTHxq3VCajZ52DVSJxMgerW7TeGc2s23MQFy6jfh",
        },
        "chain_ext": {
            "ex_pub": "tpubDEzFEQfaxP49i2QvMkgWqq4QqTZHyLQQbKPE8qZk8ibsWz3gGazGtQiNjKjQbbtpNPxfG4FC3YDomxqVRaQD2gx7y54NEobb7EZQk6UY2Fb",
            "ex_priv": "GPvmpiP7xcyAK5ZRuHcYFZGZwrGe5vP3XVSzJYPn5bz2JZqjK6jbZMdRojayw1dtLcd4GSi5zuSyHtmCinrvexJHuFwE8byos4reSerwdxCtEKqnkFxKnoHehoNJLzXknodckAsveHFWNUW9bBTy7GXRzPd",
        },
        "addresses": [
            "addr_test1qzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969y7r3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qy0adz0",
            "addr_test1qqg8whf7u4sjlw0fjapgyf6jzayx7svd9xqsv6thymk7s3kr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qlqy8vr",
            "addr_test1qr5q038lxyc2dftwxqt80fgxm49h2l8pya7s9cvrvx6478xr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qtnynda",
            "addr_test1qzv9q3hkjjhel8vgvrgfl6fpfyax55wpctuwtqfa7veyj6kr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0qp68xhy",
            "addr_test1qrchn3ekmz9f44vkzywy93uujpg4pmpgsva7jgkvqf7ahrxr3y3kdut55a40jff00qmg74686vz44v6k363md06qkq0q04a9re",
        ],
        "staking_address": "stake_test1urpcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8s8ke268",
    },
    # Cardano test net (Ledger)
    {
        "coin": Cip1852Coins.CARDANO_LEDGER_TESTNET,
        "names": ("Cardano TestNet", "ADA"),
        "is_testnet": True,
        "seed": b"0000000000000000000000000000000000000000",
        "ex_master": "GPvmpfpp1e1m4t8kWzDJrmESrR8TcLzLprdfw3TPjYuSG2rWxYFatx5EQ2v6mWxrc3J6f8Vp8PGBAhpeF6fyZiDgL7F4pzR5xBzDUtFWcry1B23eYk1NRc1iUDKxq5KZUHGzL1niqC8z7XBW91omX2ho9hu",
        "wif_master": "",
        "account": {
            "ex_pub": "tpubDCVdxE3NWm9Ynj4ZGC3Q2vswsy2KYRNv4tTPjJxpmEH52hnquLurKWGPytmpJvZfo94frXzWGLphoVKBbDpHEEVVNSuVLfD1wGRzU1dcotM",
            "ex_priv": "GPvmpheARAgbHojJBjNuRpJSeoWoWqqn9fxpPJk33cxHNMHoDibGgvHgKaTphCxoQF8QhBFnhQZtyLuQMVW5QubnyPPhEymuBmHYhdLRRQPX8nRrTQy2abNG9ZHr2oEGCL47ee3v2TQFXEPL7TBFkPDsngs",
        },
        "chain_ext": {
            "ex_pub": "tpubDE17JMfkat7pMNvirR5Abc7nfTF7qkg4RAmHY4gS1TdZkMn73qSfi3ZuDkHuYJHff9HwVp1obQeVma8DnyvPVkg3MvxVWBjRcXdwME3fi7i",
            "ex_priv": "GPvmpi69WuLXmhmWAk1m8uoXZTY8qWAPXybeZRhcNF2C6QyKegHUUD88GzMsgAjx7ZeHxNfod3dA9xJ4XTbLxe9Jizuepx4tPA27GkM6ZEYBodrMGQGotg68i4XYKm4mfo6G8CEGAxyXxfHiiQLYLpgqfna",
        },
        "addresses": [
            "addr_test1qpug2zur0nmy0pwjk023cnzxlru6vc3rw67r9qlsufjg5rtsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuks9zqk3c",
            "addr_test1qz6yq2qe4cje59azajeg3eqzh79kglps5qq5xmx9pdu2mctsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuks0jmusg",
            "addr_test1qzrtelvca45kah8vszqpnurvcpdkwy9wfmph20eldu53wlmsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksgmyydr",
            "addr_test1qzu62njn5uqnjuje09yakmzzxh35w8dh0z32aranp3qdm8msgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksz8aelv",
            "addr_test1qptya3ymcmrtvty0gfr8qv9mwe4flytjydlsk6ju776583nsgz3vs9ld89vhmvmnhhazr2tdgxkgq9xu8mzzlwwxvuksesmfyp",
        ],
        "staking_address": "stake_test1upcypgkgzlknjktakdemm73p49k5rtyqznwra3p0h8rxwtggxc7hx",
    },
]

# Tests for default path derivation (not possible with CIP-1852)
TEST_VECT_DEFAULT_PATH = []

# Tests for different key formats
TEST_VECT_KEY_FORMATS = {
    "coin": Cip1852Coins.CARDANO_ICARUS,
    "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    "ex_priv": "xprv3QESAWYc9vDdZe96kW68FGJoM5SDWc6n7PMG2GYMQugVExnn5XPBvH2JtT5LvKU34bp1Zv8yEG7hsznPrC3tfVbJUeRxS6abLUKQy8kgNRYx49aEeTKCvqezGNxib9NjSxYgXkH2xh4RgkSccNK7HAf",
    "raw_priv": "90fe045d7c56df39574eff1ce14c49844f758fa20139947425df74bc8647ae4069ea9658ff974de1b3c967febc9c40771cb1de416e6db0a61394803f245d06f8",
    "ex_pub": "xpub661MyMwAqRbcFoZEHCepczoPjV1qDcqqwxX2WpoSKRQ3nQBXSsyMKmKxx6fHNcQ5znKZtV76QwMGscjbzj1ooF87Rk1o6rLnHteGz4Vsrwu",
    "raw_compr_pub": "0050715791b0a6d1b7e3944299dd24ff12f8dc5f7820440775ff8e3330e89ee463",
    "raw_uncompr_pub": "0050715791b0a6d1b7e3944299dd24ff12f8dc5f7820440775ff8e3330e89ee463",
}

# Tests for extended keys with valid and invalid depths
TEST_VECT_EX_KEY_DEPTHS = {
    # Private key with depth 5 is fine
    "ex_priv_5": "xprv3TXkBmYndbYFHWR2C2iBDE1Zfo8QCtCEYU5EFriquAw4pcfruRW7nvpWkkNPy5owQCRfjJ8UgbgeuWMBK47hxKfLyFKLcRKxMsLhwSkFAWZ2pVXx7NwRxsN8k6shqNeGJNKwCtrckrAj8geHNZnP5NP",
    # Private key with depth 6 shall raise an exception
    "ex_priv_6": "xprv3U1vuqPfgtKUYU72uaLrXm9cUSeyW487qN8rihLEuQt57y37UDJtMMTE3yPX9h3x1KtbwtoKirLMMiVRxoZjnVgqVhqUHSV1E6ceR6HZvQGKqhLRN53YH5KSPPjpgUtPcgNKTWBLEdy5s6moGzWiLys",
    # Public key with depth 2 shall raise an exception
    "ex_pub_2": "xpub6A4tnUjutEhspSy1HiG6wzfcfZkypeAto6txryTRKbGeacQHzatSRvB74iMgazgzTruzAgx8qv66c8GYKiCwZFjDMugqZinLtg9CwekG2bi",
    # Public key with depth 3 shall raise an exception
    "ex_pub_3": "xpub6BniHFwoM7UXKxz5seh2aM4SmhorSZXwzEqSVJkuGAwngz97ficCC5hP3GehF5u4YVKxGnXMFFgjVvaxJnqU3mvLXYkgesYvJ47p9Ad2f9u",
    # Public key with depth 5 is fine
    "ex_pub_5": "xpub6H7NWc5ZSTg3LpeWyi2gzP72feZxt3uZ2HgtvVxoaneTZGEWoohRgZPnsEEHi43qPoWjpBE2TTkrqBvofFtwiVadvoazK4MqQXX6KDhEfoz",
    # Public key with depth 6 shall raise an exception
    "ex_pub_6": "xpub6JkFVCnTDbtyfn53Z1G8WHUznoWQgV6mQ5gTW18q2ZdY1q5MuaxFfaq5aQ8JAKXuWXPdJDbMJ1bzks4GhgmvqcWcQUUUCsvG2adLtYsy2iW",
}


#
# Tests
#
class Cip1852Tests(Bip44BaseTests):
    # Test specification name
    def test_spec_name(self):
        self.assertEqual(Cip1852.SpecName(), "CIP-1852")

    # Run all tests in test vector using FromSeed for construction
    def test_from_seed(self):
        self._test_from_seed(Cip1852, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(Cip1852, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(Cip1852, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(Cip1852, TEST_VECT)

    # Test default path derivation
    def test_default_path_derivation(self):
        self._test_default_path_derivation(Cip1852, TEST_VECT_DEFAULT_PATH)

    # Test for IsLevel method
    def test_is_level(self):
        self._test_is_level(Cip1852, Cip1852Coins.CARDANO_ICARUS, TEST_SEED)

    # Test different key formats
    def test_key_formats(self):
        self._test_key_formats(Cip1852, TEST_VECT_KEY_FORMATS)

    # Test construction from extended keys with valid and invalid depths
    def test_from_ex_key_depth(self):
        self._test_from_ex_key_depth(Cip1852, Cip1852Coins.CARDANO_ICARUS, TEST_VECT_EX_KEY_DEPTHS)

    # Test type error during construction
    def test_type_error(self):
        self._test_type_error(Cip1852, [Bip44Coins, Bip49Coins, Bip84Coins, Bip86Coins])

    # Test invalid path derivations
    def test_invalid_derivations(self):
        self._test_invalid_derivations(Cip1852, Cip1852Coins.CARDANO_ICARUS, TEST_SEED)
