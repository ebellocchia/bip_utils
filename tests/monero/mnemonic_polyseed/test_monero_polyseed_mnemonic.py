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
import unittest

from bip_utils import (
    MnemonicChecksumError,
    Monero,
    MoneroPolyseedCoins,
    MoneroPolyseedDecodedData,
    MoneroPolyseedEntropyGenerator,
    MoneroPolyseedLanguages,
    MoneroPolyseedMnemonicDecoder,
    MoneroPolyseedMnemonicEncoder,
    MoneroPolyseedMnemonicEncrypter,
    MoneroPolyseedMnemonicGenerator,
    MoneroPolyseedMnemonicValidator,
    MoneroPolyseedSeedGenerator,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_utils import (
    MoneroPolyseedGf,
    MoneroPolyseedMnemonicUtils,
)


# Verified with polyseed C reference (tests.c) and Cake Wallet
TEST_VECT = [
    # English
    {
        "entropy": b"64b61f808a53fd0033c59f7cbefa40040ede30",
        "mnemonic": "goddess goose success way card fatigue village adapt vanish palm very use mosquito advice derive umbrella",
        "seed": b"b4065b99aab59820d945e9fb373f8348e4b9b9256b469634f7bb8925720785db",
        "priv_skey": "ab43dfe053ada9a7f64e56b5e98e3039e3b9b9256b469634f7bb89257207850b",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.ENGLISH,
    },
    {
        "entropy": b"119366f48584c57e1f08e434e0e799a2d3ef0c",
        "mnemonic": "pill balance eternal hungry candy luggage beyond tide search tomato squirrel atom toy pepper exile veteran",
        "seed": b"c16f2c8a509758d2e15647811deaa887b403a21fd21866e8b631c4891bcd9699",
        "priv_skey": "6cfc8745631bb3b958d392c64921d2cbb303a21fd21866e8b631c4891bcd9609",
        "birthday": 1759366062,
        "features": 0,
        "coin": MoneroPolyseedCoins.AEON,
        "lang": MoneroPolyseedLanguages.ENGLISH,
    },
    {
        "entropy": b"45ad3896a46b3f7e882e2432f8bf1b435bdf20",
        "mnemonic": "airport easy regular matter poverty help worry trigger argue catch slogan mesh shoulder drop hunt wealth",
        "seed": b"c0a931e820ea44817e9659171e752bcb02f5d916beaf24395ef61384237fb2ed",
        "priv_skey": "ca12c0d2af7e43b0c502cf2df1caf9a601f5d916beaf24395ef61384237fb20d",
        "birthday": 1759366062,
        "features": 0,
        "coin": MoneroPolyseedCoins.WOWNERO,
        "lang": MoneroPolyseedLanguages.ENGLISH,
    },
    # French
    {
        "entropy": b"d9b8bf3539b5e67dcc2db6fa820013d535f513",
        "mnemonic": "aménager séjour strict unifier édifier pénétrer mensonge signal ambre période terrible bolide adepte saisir science enlever",
        "seed": b"30b6e09804593c2f087f7c6237f8bb1be50be9235121e5d9d1adbeeaed65f7a2",
        "priv_skey": "ee6e46f7fc7984bea85ed0048535064be40be9235121e5d9d1adbeeaed65f702",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.FRENCH,
    },
    # French
    {
        "entropy": b"d9b8bf3539b5e67dcc2db6fa820013d535f513",
        "mnemonic": "aménager séjour strict unifier édifier pénétrer mensonge signal ambre période terrible bolide adepte saisir science enlever",
        "seed": b"30b6e09804593c2f087f7c6237f8bb1be50be9235121e5d9d1adbeeaed65f7a2",
        "priv_skey": "ee6e46f7fc7984bea85ed0048535064be40be9235121e5d9d1adbeeaed65f702",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.FRENCH,
    },
    # Italian
    {
        "entropy": b"24ee6a3994ff98ee5a41b6e9a55aef49ba0136",
        "mnemonic": "magico canapa ritardo poderoso illogico zucchero icona tesi ombra rinforzo potassio foresta rollio esercito tombola birra",
        "seed": b"951aefdc90c9099f3c6db65f885cc400d3d5bed9599fd7ff894e70b52caddba4",
        "priv_skey": "53d3543b89ea512edd4c0a02d6990e30d2d5bed9599fd7ff894e70b52caddb04",
        "birthday": 1748847078,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.ITALIAN,
    },
    # Portuguese
    {
        "entropy": b"0b8a11623f108d9378b4898cc6b4f206afd302",
        "mnemonic": "sonhador alecrim boreal argola lesma anagrama chave chumbo caixote juba caule foguete comando adjunto poluente capricho",
        "seed": b"268f74831e2c36ab2ddcd2906501c7b6340d2af41713ea0cd68a287cb9cd10c4",
        "priv_skey": "0aa0ee27e286598a218237edf54a53bc330d2af41713ea0cd68a287cb9cd1004",
        "birthday": 1748847078,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.PORTUGUESE,
    },
    # Korean
    {
        "entropy": b"61b026a390ceffaafafa0d91a0a73decdae00e",
        "mnemonic": "한문 삼십 제작 성별 퇴근 차라리 흐름 자동 정성 계층 박수 결정 차선 하숙집 센티미터 갈증",
        "seed": b"7f8c6afe5ccb2bdb17921f09d8d374b6061026d08d078bead1257ddc41de803f",
        "priv_skey": "b81089e70da2f4d294bb38203ce6d777061026d08d078bead1257ddc41de800f",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.KOREAN,
    },
    # Chinese (simplified)
    {
        "entropy": b"5945337c834b7265b9086e82267f35ad711627",
        "mnemonic": "录 罗 意 标 色 范 锁 汽 举 倍 部 乱 驱 栏 浅 迫",
        "seed": b"2e4ae471382d7bd0f46a34062c0441bdaf035e5994cc6c57c76c6935e0ae2839",
        "priv_skey": "67ce025be90344c871944d1d9016a47eaf035e5994cc6c57c76c6935e0ae2809",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.CHINESE_SIMPLIFIED,
    },
    # Chinese (traditional)
    {
        "entropy": b"0607a103aa98cfce38c1fa67ce5eae71548320",
        "mnemonic": "善 產 放 表 仗 藏 蘇 弓 音 徙 盪 穆 緣 套 站 候",
        "seed": b"a81fe6d22722a6bed00d2dda64fe9c09eac37feabeb2845c6590e21ce75f3c92",
        "priv_skey": "53ac418e3aa600a6478a781f9135c64de9c37feabeb2845c6590e21ce75f3c02",
        "birthday": 1769885046,
        "features": 0,
        "coin": MoneroPolyseedCoins.MONERO,
        "lang": MoneroPolyseedLanguages.CHINESE_TRADITIONAL,
    },
]

# Test for mnemonic encryption/decryption
TEST_VECT_ENCRYPT_DECRYPT = [
    {
        "mnemonic_dec": "goddess goose success way card fatigue village adapt vanish palm very use mosquito advice derive umbrell",
        "mnemonic_enc": "science shell void cruel traffic travel ribbon adult speak seat cup view knock oak lens early",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.ENGLISH,
    },
    {
        "mnemonic_dec": "grotte malheur féroce tituber vérin forgeron blague déclarer joindre sanction suggérer chiot cribler miauler étoile numéro",
        "mnemonic_enc": "nrouille coiffer domaine bonheur cuisine soleil enfance débrider nourrir jupon brillant cellule rocheux ailier tapis antidote",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.FRENCH,
    },
    {
        "mnemonic_dec": "magico canapa ritardo poderoso illogico zucchero icona tesi ombra rinforzo potassio foresta rollio esercito tombola birra",
        "mnemonic_enc": "sociale mulatto oscurare lanterna pimpante etnico colmato terrazzo renna trespolo gregge esigente femmina spronato florido ridicolo",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.ITALIAN,
    },
    {
        "mnemonic_dec": "sonhador alecrim boreal argola lesma anagrama chave chumbo caixote juba caule foguete comando adjunto poluente capricho",
        "mnemonic_enc": "cultura nupcial adepto secular desviar muscular hesitar chocalho alicate roseira urso gralha sagrada luva aclamar marmita",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.PORTUGUESE,
    },
    {
        "mnemonic_dec": "한문 삼십 제작 성별 퇴근 차라리 흐름 자동 정성 계층 박수 결정 차선 하숙집 센티미터 갈증",
        "mnemonic_enc": "본인 제일 하천 이별 기본 시중 장래 자격 원인 별명 아나운서 교장 낙엽 실수 창가 인체",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.KOREAN,
    },
    {
        "mnemonic_dec": "录 罗 意 标 色 范 锁 汽 举 倍 部 乱 驱 栏 浅 迫",
        "mnemonic_enc": "陕 萄 查 莲 叙 卿 刀 终 啊 青 叛 赶 更 官 堂 疗",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.CHINESE_SIMPLIFIED,
    },
    {
        "mnemonic_dec": "善 產 放 表 仗 藏 蘇 弓 音 徙 盪 穆 緣 套 站 候",
        "mnemonic_enc": "臂 壯 半 虧 律 況 憲 酷 你 拖 測 檔 談 煮 脆 婦",
        "password": "my_password",
        "lang": MoneroPolyseedLanguages.CHINESE_TRADITIONAL,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "abandon abandon abandon",
        "exception": ValueError,
    },
    # Wrong checksum (last word changed)
    {
        "mnemonic": "raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport abandon",
        "exception": MnemonicChecksumError,
    },
    # Not existent word
    {
        "mnemonic": "raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport notexistent",
        "exception": ValueError,
    },
    # Wrong coin
    {
        "mnemonic": "raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport language",
        "coin": MoneroPolyseedCoins.AEON,
        "exception": MnemonicChecksumError,
    },
]


#
# Tests
#
class MoneroPolyseedMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            coin = test["coin"]
            lang = test["lang"]

            # Test mnemonic encoder
            encoder = MoneroPolyseedMnemonicEncoder(lang)
            mnemonic = encoder.EncodeWithData(
                binascii.unhexlify(test["entropy"]),
                test["birthday"],
                test["features"],
                coin,
            )
            self.assertEqual(test["mnemonic"], mnemonic.ToStr())
            self.assertEqual(test["mnemonic"], str(mnemonic))
            self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
            self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())

            # Test mnemonic validator
            mnemonic_validator = MoneroPolyseedMnemonicValidator(coin, lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            mnemonic_validator.Validate(mnemonic)

            # Test mnemonic decoder
            decoder = MoneroPolyseedMnemonicDecoder(coin, lang)
            data = decoder.DecodeWithData(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(data.secret))
            self.assertEqual(test["birthday"], data.birthday_timestamp)
            self.assertEqual(test["features"], data.user_features)

            # Test decoder (returns just secret bytes)
            entropy = decoder.Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))

            # Test seed generator
            seed = MoneroPolyseedSeedGenerator(mnemonic, coin, lang).Generate()
            self.assertEqual(test["seed"], binascii.hexlify(seed))

            # Test private key
            monero = Monero.FromSeed(seed)
            self.assertEqual(test["priv_skey"], monero.PrivateSpendKey().Raw().ToHex())

    # Test entropy generator
    def test_entropy_generator(self):
        gen = MoneroPolyseedEntropyGenerator()
        entropy = gen.Generate()
        self.assertEqual(len(entropy), 19)
        # Top 2 bits of last byte should be cleared
        self.assertEqual(entropy[-1] & 0xC0, 0)

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        self.assertTrue(MoneroPolyseedEntropyGenerator.IsValidEntropyBitLen(150))
        self.assertFalse(MoneroPolyseedEntropyGenerator.IsValidEntropyBitLen(128))
        self.assertFalse(MoneroPolyseedEntropyGenerator.IsValidEntropyBitLen(256))
        self.assertTrue(MoneroPolyseedEntropyGenerator.IsValidEntropyByteLen(19))
        self.assertFalse(MoneroPolyseedEntropyGenerator.IsValidEntropyByteLen(18))
        self.assertFalse(MoneroPolyseedEntropyGenerator.IsValidEntropyByteLen(20))

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        self.assertRaises(ValueError, MoneroPolyseedEntropyGenerator, 128)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        gen = MoneroPolyseedMnemonicGenerator(MoneroPolyseedLanguages.ENGLISH)
        mnemonic = gen.FromRandom()
        self.assertEqual(mnemonic.WordsCount(), 16)

        # Verify it can be decoded
        decoder = MoneroPolyseedMnemonicDecoder(MoneroPolyseedCoins.MONERO)
        data = decoder.DecodeWithData(mnemonic)
        self.assertEqual(data.features, 0)

    # Test Encode (uses current time as birthday)
    def test_encode(self):
        test = TEST_VECT[0]
        encoder = MoneroPolyseedMnemonicEncoder(test["lang"])
        mnemonic = encoder.Encode(binascii.unhexlify(test["entropy"]))
        self.assertEqual(mnemonic.WordsCount(), 16)

        # Verify it can be decoded and has the correct secret
        decoder = MoneroPolyseedMnemonicDecoder(test["coin"])
        data = decoder.DecodeWithData(mnemonic)
        self.assertEqual(data.secret, binascii.unhexlify(test["entropy"]))
        self.assertEqual(data.features, 0)

    # Test construction from invalid words number (invalid entropy length)
    def test_from_invalid_entropy_len(self):
        encoder = MoneroPolyseedMnemonicEncoder()
        self.assertRaises(ValueError, encoder.Encode, b"\x00" * 16)
        self.assertRaises(ValueError, encoder.Encode, b"\x00" * 20)
        self.assertRaises(ValueError, encoder.EncodeWithData, b"\x00" * 16, 0, 0)
        self.assertRaises(ValueError, encoder.EncodeWithData, b"\x00" * 20, 0, 0)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            coin = test.get("coin", MoneroPolyseedCoins.MONERO)

            self.assertFalse(MoneroPolyseedMnemonicValidator(coin).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], MoneroPolyseedMnemonicValidator(coin).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], MoneroPolyseedMnemonicDecoder(coin).Decode, test["mnemonic"])

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, MoneroPolyseedMnemonicEncoder, 0)
        self.assertRaises(TypeError, MoneroPolyseedMnemonicDecoder, MoneroPolyseedCoins.MONERO, 0)

    # Test encoding/decoding roundtrip for all supported languages
    def test_roundtrip_all_languages(self):
        test = TEST_VECT[0]
        secret = binascii.unhexlify(test["entropy"])
        coin = test["coin"]

        for lang in MoneroPolyseedLanguages:
            encoder = MoneroPolyseedMnemonicEncoder(lang)
            mnemonic = encoder.EncodeWithData(
                secret,
                test["birthday"],
                test["features"],
                coin,
            )
            self.assertEqual(mnemonic.WordsCount(), 16)

            decoder = MoneroPolyseedMnemonicDecoder(coin)
            data = decoder.DecodeWithData(mnemonic)
            self.assertEqual(data.secret, secret)
            self.assertEqual(data.birthday_timestamp, test["birthday"])
            self.assertEqual(data.user_features, test["features"])

    # Test coin domain separation
    def test_coin_domain_separation(self):
        test = TEST_VECT[0]
        encoder = MoneroPolyseedMnemonicEncoder(MoneroPolyseedLanguages.ENGLISH)
        secret = binascii.unhexlify(test["entropy"])

        mnemonic_monero = encoder.EncodeWithData(secret, test["birthday"], 0, MoneroPolyseedCoins.MONERO)
        mnemonic_aeon = encoder.EncodeWithData(secret, test["birthday"], 0, MoneroPolyseedCoins.AEON)

        self.assertNotEqual(mnemonic_monero.ToStr(), mnemonic_aeon.ToStr())

        # Each should decode correctly with its own coin
        self.assertEqual(MoneroPolyseedMnemonicDecoder(MoneroPolyseedCoins.MONERO).Decode(mnemonic_monero), secret)
        self.assertEqual(MoneroPolyseedMnemonicDecoder(MoneroPolyseedCoins.AEON).Decode(mnemonic_aeon), secret)

        # Cross-coin should fail
        self.assertRaises(MnemonicChecksumError, MoneroPolyseedMnemonicDecoder(MoneroPolyseedCoins.MONERO).Decode, mnemonic_aeon)

    # Test encoding/decoding with feature flags
    def test_encode_decode_with_features(self):
        test = TEST_VECT[0]
        encoder = MoneroPolyseedMnemonicEncoder(test["lang"])
        mnemonic = encoder.EncodeWithData(
            binascii.unhexlify(test["entropy"]),
            test["birthday"],
            1,
            test["coin"],
        )
        self.assertEqual(mnemonic.WordsCount(), 16)

        decoder = MoneroPolyseedMnemonicDecoder(test["coin"])
        data = decoder.DecodeWithData(mnemonic)
        self.assertEqual(data.secret, binascii.unhexlify(test["entropy"]))
        self.assertEqual(data.birthday_timestamp, test["birthday"])
        self.assertEqual(data.features, 1)
        self.assertEqual(data.user_features, 1)

    # Test decoded data properties
    def test_decoded_data_properties(self):
        data = MoneroPolyseedDecodedData(
            secret=b"\x00" * 19,
            birthday=1,
            features=0,
            checksum=0,
        )
        self.assertFalse(data.is_encrypted)
        self.assertEqual(data.user_features, 0)
        self.assertEqual(data.birthday_timestamp, 1635768000 + 2629746)

        # With encrypted flag
        data_enc = MoneroPolyseedDecodedData(
            secret=b"\x00" * 19,
            birthday=1,
            features=16,  # ENCRYPTED_MASK
            checksum=0,
        )
        self.assertTrue(data_enc.is_encrypted)

    # Test encryption/decryption roundtrip
    def test_encryption_roundtrip(self):
        test = TEST_VECT[0]
        password = TEST_VECT_ENCRYPT_DECRYPT[0]["password"]

        # Decode mnemonic to get original data
        decoder = MoneroPolyseedMnemonicDecoder(test["coin"], test["lang"])
        original_data = decoder.DecodeWithData(test["mnemonic"])

        # Encrypt
        encrypted = MoneroPolyseedMnemonicEncrypter.Crypt(original_data, password)
        self.assertTrue(encrypted.is_encrypted)
        self.assertNotEqual(encrypted.secret, original_data.secret)

        # Decrypt
        decrypted = MoneroPolyseedMnemonicEncrypter.Crypt(encrypted, password)
        self.assertFalse(decrypted.is_encrypted)
        self.assertEqual(decrypted.secret, original_data.secret)
        self.assertEqual(decrypted.birthday, original_data.birthday)
        self.assertEqual(decrypted.features, original_data.features)

    # Test encrypted encode/decode roundtrip
    def test_encrypted_encode_decode_roundtrip(self):
        test = TEST_VECT[0]
        password = TEST_VECT_ENCRYPT_DECRYPT[0]["password"]

        # Decode mnemonic to get original data
        decoder = MoneroPolyseedMnemonicDecoder(test["coin"], test["lang"])
        original_data = decoder.DecodeWithData(test["mnemonic"])

        # Encrypt
        encrypted = MoneroPolyseedMnemonicEncrypter.Crypt(original_data, password)

        # Encode encrypted data
        encoder = MoneroPolyseedMnemonicEncoder(test["lang"])
        mnemonic = encoder.EncodeData(encrypted, test["coin"])

        # Decode
        decoded = decoder.DecodeWithData(mnemonic)
        self.assertTrue(decoded.is_encrypted)

        # Decrypt
        decrypted = MoneroPolyseedMnemonicEncrypter.Crypt(decoded, password)
        self.assertFalse(decrypted.is_encrypted)
        self.assertEqual(decrypted.secret, original_data.secret)

    # Test GF(2048) arithmetic
    def test_gf_arithmetic(self):
        # ElemMul2: below 1024 is simple doubling
        self.assertEqual(MoneroPolyseedGf.ElemMul2(0), 0)
        self.assertEqual(MoneroPolyseedGf.ElemMul2(1), 2)
        self.assertEqual(MoneroPolyseedGf.ElemMul2(512), 1024)
        # At and above 1024: uses lookup table
        self.assertEqual(MoneroPolyseedGf.ElemMul2(1024), 5)
        self.assertEqual(MoneroPolyseedGf.ElemMul2(1025), 7)

        # PolyCheck: valid polynomial should pass, corrupted should fail
        data = MoneroPolyseedDecodedData(
            secret=binascii.unhexlify(TEST_VECT[0]["entropy"]),
            birthday=TEST_VECT[0]["birthday"],
            features=TEST_VECT[0]["features"],
            checksum=0,
        )
        coeffs = MoneroPolyseedMnemonicUtils.DataToPoly(data)
        MoneroPolyseedGf.PolyEncode(coeffs)
        self.assertTrue(MoneroPolyseedGf.PolyCheck(coeffs))
        coeffs[5] ^= 1
        self.assertFalse(MoneroPolyseedGf.PolyCheck(coeffs))

    # Test DataToPoly -> PolyToData roundtrip
    def test_data_to_poly_roundtrip(self):
        test = TEST_VECT[0]
        birthday = MoneroPolyseedMnemonicUtils.BirthdayEncode(test["birthday"])

        data = MoneroPolyseedDecodedData(
            secret=binascii.unhexlify(test["entropy"]),
            birthday=birthday,
            features=test["features"],
            checksum=0,
        )
        coeffs = MoneroPolyseedMnemonicUtils.DataToPoly(data)
        MoneroPolyseedGf.PolyEncode(coeffs)
        recovered = MoneroPolyseedMnemonicUtils.PolyToData(coeffs)

        self.assertEqual(recovered.secret, data.secret)
        self.assertEqual(recovered.birthday, data.birthday)
        self.assertEqual(recovered.features, data.features)

    # Test birthday encode/decode
    def test_birthday_encode_decode(self):
        test_birthday = TEST_VECT[0]["birthday"]
        test_birthday_encoded = MoneroPolyseedMnemonicUtils.BirthdayEncode(test_birthday)

        # Known timestamps
        self.assertEqual(MoneroPolyseedMnemonicUtils.BirthdayEncode(1638446400), 1)
        self.assertGreater(test_birthday_encoded, 0)
        # Before epoch
        self.assertEqual(MoneroPolyseedMnemonicUtils.BirthdayEncode(0), 0)
        self.assertEqual(MoneroPolyseedMnemonicUtils.BirthdayEncode(1000000000), 0)

        # Decode and verify it roundtrips approximately
        for birthday, original_time in [(1, 1638446400), (test_birthday_encoded, test_birthday)]:
            decoded = MoneroPolyseedMnemonicUtils.BirthdayDecode(birthday)
            self.assertLessEqual(decoded, original_time)
            self.assertGreater(decoded + 2630000, original_time)
