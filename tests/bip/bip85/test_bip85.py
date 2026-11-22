# Copyright (c) 2026 Emanuele Bellocchia
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
import hashlib
import math
import unittest

from bip_utils import (
    Bip32KeyData,
    Bip32PathError,
    Bip32Slip10Ed25519,
    Bip32Slip10Nist256p1,
    Bip32Slip10Secp256k1,
    Bip39Languages,
    Bip39MnemonicEncoder,
    Bip39WordsNum,
    Bip85,
    Bip85Drng,
)
from bip_utils.bip.bip32.bip32_const import Bip32Const
from tests.bip.bip32.test_bip32_base import TEST_SEED


# Master key used by all the test vectors of BIP-0085
TEST_MASTER_KEY = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

# All the following test vectors are taken from BIP-0085:
# https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki

# Tests for entropy derivation
TEST_VECT_ENTROPY = [
    {
        "path": "m/83696968'/0'/0'",
        "derived_key": b"cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
        "entropy": b"efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
    },
    {
        "path": "m/83696968'/0'/1'",
        "derived_key": b"503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
        "entropy": b"70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
    },
]

# Tests for DRNG
TEST_VECT_DRNG = [
    {
        "path": "m/83696968'/0'/0'",
        "drng_bytes": b"b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111",
    },
]

# Tests for BIP39 application
TEST_VECT_BIP39 = [
    {
        "lang": Bip39Languages.ENGLISH,
        "words_num": 12,
        "index": 0,
        "mnemonic": "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
    },
    {
        "lang": Bip39Languages.ENGLISH,
        "words_num": Bip39WordsNum.WORDS_NUM_18,
        "index": 0,
        "mnemonic": "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey "
                    "outdoor supply token",
    },
    {
        "lang": Bip39Languages.ENGLISH,
        "words_num": 24,
        "index": 0,
        "mnemonic": "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight "
                    "reason outdoor destroy simple truth cigar social volcano",
    },
]

# Language codes of BIP39 application
TEST_VECT_BIP39_LANG_CODES = {
    Bip39Languages.ENGLISH: 0,
    Bip39Languages.KOREAN: 2,
    Bip39Languages.SPANISH: 3,
    Bip39Languages.CHINESE_SIMPLIFIED: 4,
    Bip39Languages.CHINESE_TRADITIONAL: 5,
    Bip39Languages.FRENCH: 6,
    Bip39Languages.ITALIAN: 7,
    Bip39Languages.CZECH: 8,
    Bip39Languages.PORTUGUESE: 9,
}

# Tests for HD-Seed WIF application
TEST_VECT_HD_SEED_WIF = [
    {
        "index": 0,
        "wif": "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp",
    },
]

# Tests for XPRV application
TEST_VECT_XPRV = [
    {
        "index": 0,
        "xprv": "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX",
    },
]

# Tests for HEX application
TEST_VECT_HEX = [
    {
        "num_bytes": 64,
        "index": 0,
        "hex": "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c",
    },
]

# Tests for PWD BASE64 application
TEST_VECT_PWD_BASE64 = [
    {
        "pwd_len": 21,
        "index": 0,
        "pwd": "dKLoepugzdVJvdL56ogNV",
    },
]

# Tests for PWD BASE85 application
TEST_VECT_PWD_BASE85 = [
    {
        "pwd_len": 12,
        "index": 0,
        "pwd": "_s`{TW89)i4`",
    },
]

# Tests for DICE application
TEST_VECT_DICE = [
    {
        "sides": 6,
        "rolls": 10,
        "index": 0,
        "roll_vals": [1, 0, 0, 2, 0, 1, 5, 5, 2, 4],
    },
]

# Tests for Nostr application
TEST_VECT_NOSTR = [
    {
        "identity": 1,
        "account_idx": 1,
        "nsec": "nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz",
    },
    {
        "identity": 1,
        "account_idx": 2,
        "nsec": "nsec1j9mzs6yk2g5g76vrezspmdgk6p5h65vcmnuaayqst9l4uv30hfhqje0jyh",
    },
    {
        "identity": 2,
        "account_idx": 1,
        "nsec": "nsec1lgh8ss53k87ng7arvfr89ccfpjevac6ts4n3sqekuw4zjrgzw9dsq3uelh",
    },
]

# Tests for dice with more bits per roll (checked against a reference implementation)
TEST_VECT_DICE_SIDES = [2, 255, 256, 257, 1000, 100000, 2**31 - 1]


# Reference implementation of the DICE application, written by following the BIP-0085 text
def dice_ref(entropy_bytes, sides, rolls):
    bits_per_roll = math.ceil(math.log2(sides))
    bytes_per_roll = math.ceil(bits_per_roll / 8)
    # Plenty of bytes, so that the stream is never exhausted
    stream = hashlib.shake_256(entropy_bytes).digest(bytes_per_roll * rolls * 64)

    roll_vals = []
    offset = 0
    while len(roll_vals) < rolls:
        trial = int.from_bytes(stream[offset:offset + bytes_per_roll], "big") >> (bytes_per_roll * 8 - bits_per_roll)
        offset += bytes_per_roll
        if trial < sides:
            roll_vals.append(trial)
    return roll_vals


#
# Tests
#
class Bip85Tests(unittest.TestCase):
    # Test entropy derivation
    def test_entropy(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        bip32 = Bip32Slip10Secp256k1.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_ENTROPY:
            self.assertEqual(test["derived_key"], bip32.DerivePath(test["path"]).PrivateKey().Raw().ToHex().encode())
            self.assertEqual(test["entropy"], binascii.hexlify(bip85.DeriveEntropy(test["path"])))
            # Relative path
            self.assertEqual(test["entropy"], binascii.hexlify(bip85.DeriveEntropy(test["path"][2:])))

    # Test DRNG
    def test_drng(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_DRNG:
            drng_bytes = binascii.unhexlify(test["drng_bytes"])

            drng = Bip85Drng(bip85.DeriveEntropy(test["path"]))
            self.assertEqual(drng_bytes, drng.Read(len(drng_bytes)))
            # Incremental reads shall give the same result
            drng = Bip85Drng(bip85.DeriveEntropy(test["path"]))
            self.assertEqual(drng_bytes, drng.Read(1) + drng.Read(31) + drng.Read(len(drng_bytes) - 32))

    # Test BIP39 application
    def test_bip39(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_BIP39:
            self.assertEqual(test["mnemonic"], bip85.Bip39(test["lang"], test["words_num"], test["index"]).ToStr())

    # Test BIP39 application for all languages and words numbers
    def test_bip39_all(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for lang, lang_code in TEST_VECT_BIP39_LANG_CODES.items():
            for words_num in Bip39WordsNum:
                entropy_bytes = bip85.DeriveEntropy(f"m/83696968'/39'/{lang_code}'/{int(words_num)}'/1'")
                mnemonic = bip85.Bip39(lang, words_num, 1)

                self.assertEqual(words_num, mnemonic.WordsCount())
                self.assertEqual(Bip39MnemonicEncoder(lang).Encode(entropy_bytes[:words_num * 4 // 3]).ToStr(),
                                 mnemonic.ToStr())

    # Test HD-Seed WIF application
    def test_hd_seed_wif(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_HD_SEED_WIF:
            self.assertEqual(test["wif"], bip85.HdSeedWif(test["index"]))

    # Test XPRV application
    def test_xprv(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_XPRV:
            self.assertEqual(test["xprv"], bip85.Xprv(test["index"]))

    # Test XPRV application with a test net master key
    def test_xprv_testnet(self):
        bip32 = Bip32Slip10Secp256k1.FromExtendedKey(TEST_MASTER_KEY)
        bip85_test = Bip85(
            Bip32Slip10Secp256k1.FromPrivateKey(bip32.PrivateKey().Raw().ToBytes(),
                                                Bip32KeyData(chain_code=bip32.ChainCode()),
                                                Bip32Const.TEST_NET_KEY_NET_VERSIONS)
        )
        for test in TEST_VECT_XPRV:
            tprv = bip85_test.Xprv(test["index"])
            self.assertTrue(tprv.startswith("tprv"))

            # Same key and chain code of the main net one
            bip32_xprv = Bip32Slip10Secp256k1.FromExtendedKey(test["xprv"])
            bip32_tprv = Bip32Slip10Secp256k1.FromExtendedKey(tprv, Bip32Const.TEST_NET_KEY_NET_VERSIONS)
            self.assertEqual(bip32_xprv.PrivateKey().Raw().ToBytes(), bip32_tprv.PrivateKey().Raw().ToBytes())
            self.assertEqual(bip32_xprv.ChainCode().ToBytes(), bip32_tprv.ChainCode().ToBytes())

    # Test HEX application
    def test_hex(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_HEX:
            self.assertEqual(test["hex"], bip85.Hex(test["num_bytes"], test["index"]))

        # Truncation
        for num_bytes in (16, 32, 63):
            entropy_bytes = bip85.DeriveEntropy(f"m/83696968'/128169'/{num_bytes}'/0'")
            self.assertEqual(entropy_bytes[:num_bytes].hex(), bip85.Hex(num_bytes, 0))

    # Test PWD BASE64 application
    def test_pwd_base64(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_PWD_BASE64:
            self.assertEqual(test["pwd"], bip85.PwdBase64(test["pwd_len"], test["index"]))

        # Limits (no padding in the longest password)
        self.assertEqual(20, len(bip85.PwdBase64(20, 0)))
        self.assertEqual(86, len(bip85.PwdBase64(86, 0)))
        self.assertNotIn("=", bip85.PwdBase64(86, 0))

    # Test PWD BASE85 application
    def test_pwd_base85(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_PWD_BASE85:
            self.assertEqual(test["pwd"], bip85.PwdBase85(test["pwd_len"], test["index"]))

        # Limits
        self.assertEqual(10, len(bip85.PwdBase85(10, 0)))
        self.assertEqual(80, len(bip85.PwdBase85(80, 0)))

    # Test DICE application
    def test_dice(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_DICE:
            self.assertEqual(test["roll_vals"], bip85.Dice(test["sides"], test["rolls"], test["index"]))

    # Test DICE application with different sides number
    def test_dice_sides(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        rolls = 20
        for sides in TEST_VECT_DICE_SIDES:
            entropy_bytes = bip85.DeriveEntropy(f"m/83696968'/89101'/{sides}'/{rolls}'/0'")
            roll_vals = bip85.Dice(sides, rolls, 0)

            self.assertEqual(rolls, len(roll_vals))
            self.assertTrue(all(0 <= roll_val < sides for roll_val in roll_vals))
            self.assertEqual(dice_ref(entropy_bytes, sides, rolls), roll_vals)

    # Test Nostr application
    def test_nostr(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)
        for test in TEST_VECT_NOSTR:
            self.assertEqual(test["nsec"], bip85.Nostr(test["identity"], test["account_idx"]))

    # Test construction
    def test_construction(self):
        bip32 = Bip32Slip10Secp256k1.FromSeed(TEST_SEED)
        bip85 = Bip85(bip32)
        self.assertIs(bip32, bip85.Bip32Object())

        bip85_seed = Bip85.FromSeed(TEST_SEED)
        bip85_ex_key = Bip85.FromExtendedKey(bip32.PrivateKey().ToExtended())
        for bip85_obj in (bip85_seed, bip85_ex_key):
            self.assertEqual(bip32.PrivateKey().ToExtended(), bip85_obj.Bip32Object().PrivateKey().ToExtended())
            self.assertEqual(bip85.DeriveEntropy("m/83696968'/0'/0'"), bip85_obj.DeriveEntropy("m/83696968'/0'/0'"))

        # Key net versions are kept
        bip85_test = Bip85.FromSeed(TEST_SEED, Bip32Const.TEST_NET_KEY_NET_VERSIONS)
        self.assertTrue(bip85_test.Bip32Object().PrivateKey().ToExtended().startswith("tprv"))
        self.assertTrue(bip85_test.Xprv(0).startswith("tprv"))

    # Test invalid construction
    def test_invalid_construction(self):
        bip32 = Bip32Slip10Secp256k1.FromExtendedKey(TEST_MASTER_KEY)

        # Not secp256k1
        self.assertRaises(TypeError, Bip85, Bip32Slip10Ed25519.FromSeed(TEST_SEED))
        self.assertRaises(TypeError, Bip85, Bip32Slip10Nist256p1.FromSeed(TEST_SEED))
        # Public-only
        self.assertRaises(ValueError, Bip85.FromExtendedKey, bip32.PublicKey().ToExtended())
        # Not a master key
        self.assertRaises(ValueError, Bip85.FromExtendedKey, bip32.DerivePath("0'").PrivateKey().ToExtended())
        self.assertRaises(ValueError, Bip85, bip32.DerivePath("83696968'"))

    # Test invalid parameters
    def test_invalid_params(self):
        bip85 = Bip85.FromExtendedKey(TEST_MASTER_KEY)

        # Entropy derivation
        self.assertRaises(ValueError, bip85.DeriveEntropy, "m")
        self.assertRaises(ValueError, bip85.DeriveEntropy, "m/83696968'/0'/0")
        self.assertRaises(ValueError, bip85.DeriveEntropy, "m/83696968/0'/0'")
        self.assertRaises(Bip32PathError, bip85.DeriveEntropy, "m/83696968'/0'/a'")
        # BIP39
        self.assertRaises(TypeError, bip85.Bip39, 0, 12, 0)
        for words_num in (11, 13, 25):
            self.assertRaises(ValueError, bip85.Bip39, Bip39Languages.ENGLISH, words_num, 0)
        # Indexes
        for index in (-1, 2**31):
            self.assertRaises(ValueError, bip85.Bip39, Bip39Languages.ENGLISH, 12, index)
            self.assertRaises(ValueError, bip85.HdSeedWif, index)
            self.assertRaises(ValueError, bip85.Xprv, index)
            self.assertRaises(ValueError, bip85.Hex, 32, index)
            self.assertRaises(ValueError, bip85.PwdBase64, 20, index)
            self.assertRaises(ValueError, bip85.PwdBase85, 10, index)
            self.assertRaises(ValueError, bip85.Dice, 6, 10, index)
        # HEX
        for num_bytes in (15, 65):
            self.assertRaises(ValueError, bip85.Hex, num_bytes, 0)
        # PWD BASE64
        for pwd_len in (19, 87):
            self.assertRaises(ValueError, bip85.PwdBase64, pwd_len, 0)
        # PWD BASE85
        for pwd_len in (9, 81):
            self.assertRaises(ValueError, bip85.PwdBase85, pwd_len, 0)
        # DICE
        for sides in (1, 2**31):
            self.assertRaises(ValueError, bip85.Dice, sides, 10, 0)
        for rolls in (0, 2**31):
            self.assertRaises(ValueError, bip85.Dice, 6, rolls, 0)
        # Nostr (index 0 is reserved)
        for identity, account_idx in ((0, 1), (1, 0), (2**31, 1), (1, 2**31)):
            self.assertRaises(ValueError, bip85.Nostr, identity, account_idx)
        # DRNG
        for entropy_len in (32, 63, 65):
            self.assertRaises(ValueError, Bip85Drng, b"\x00" * entropy_len)
