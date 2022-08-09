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
    MnemonicChecksumError, Monero, MoneroEntropyBitLen, MoneroEntropyGenerator, MoneroLanguages, MoneroMnemonicDecoder,
    MoneroMnemonicGenerator, MoneroMnemonicValidator, MoneroSeedGenerator, MoneroWordsNum
)


# Verified with the official Monero wallet and: https://xmr.llcoins.net/addresstests.html
TEST_VECT = [
    #
    # Some random mnemonics in different languages (13-words)
    #

    # English
    {
        "entropy": b"fbd0bad023e0b398be458ad3979e396d",
        "mnemonic": "niece bifocals uttered robot romance gaze faxed perfect laptop fall hold strained bifocals",
        "priv_skey": "b84a3b3996b01f2acbe5cf8a6d8b4f1211fb4a2f9b31da635f4de5af6c31a90c",
        "lang": MoneroLanguages.ENGLISH,
    },
    {
        "entropy": b"e52b3282686b5fe58043098990a06718",
        "mnemonic": "zigzags dapper purged rover erosion coal tender jackets whale twang sapling tender dapper",
        "priv_skey": "c3e71e531aabe8df920da762198b2bc559fce8b83bc1d58da333da2822af460c",
        "lang": MoneroLanguages.ENGLISH,
    },
    # Japanese
    {
        "entropy": b"2d6fb5db13bddf8a0250350d03c00480",
        "mnemonic": "だいがく なにもの たんたい けんい ぜんぶ えんしゅう はいそう つまらない どうかん うしろがみ さよく はっちゅう けんい",
        "priv_skey": "47d4424169c453d32ab2e75c52acdfdf50a0859e89678036e525e52087b30a0b",
        "lang": MoneroLanguages.JAPANESE,
    },
    {
        "entropy": b"7699f8aee583c19ad523279b05c9f858",
        "mnemonic": "たいおう はっかく そんぞく だいたい たぬき くさばな そんみん かいすいよく てんごく くらべる ぬまえび きさい そんぞく",
        "priv_skey": "2f5e5c302b22a03d6cf3dbc33c231e6a1919ea810d615c975177e2a31f0c300c",
        "lang": MoneroLanguages.JAPANESE,
    },
    # Portuguese
    {
        "entropy": b"3e04a848af943459942423383717e86f",
        "mnemonic": "intumescimento lastro rumoroso gamo iatista ritualistico lepton ragu xadrez leguminoso ocaso azoto ritualistico",
        "priv_skey": "e05f451eab1e47e078a2ddff27024e5ea231561a239f3e2550ba8a785dcb550d",
        "lang": MoneroLanguages.PORTUGUESE,
    },
    {
        "entropy": b"07bcf86eb10eda63a325a6c22d6a6220",
        "mnemonic": "emotivo imerso tigresa secura iguaria situar dinossauro guizo cidreira lauto aftosa catuaba cidreira",
        "priv_skey": "442957f2d4c5399b2672d691a13776bcb58c0625cbc4b6cc48bee13cb623dc02",
        "lang": MoneroLanguages.PORTUGUESE,
    },
    # Spanish
    {
        "entropy": b"861b6ce628654040113dd2bffc8cd46a",
        "mnemonic": "carga etnia culpa conocer rígido cifra amigo cuento algodón guiño fax parcela fax",
        "priv_skey": "0fa5b0e969e7009563d0dfcc2646d4e097a8748018e99203e431cf4f2a7cfa07",
        "lang": MoneroLanguages.SPANISH,
    },
    {
        "entropy": b"94c503fbe3f08d20672ab8a4c0b6be64",
        "mnemonic": "percha móvil mirar pasta feroz ilegal mudar revés lingote paleta azul hallar móvil",
        "priv_skey": "753febedada6f975b32db29a007b9e260be49af34de78de518478b2ce94c700f",
        "lang": MoneroLanguages.SPANISH,
    },

    #
    # Some random mnemonics in different languages (25-words)
    #

    # Chinese (simplified)
    {
        "entropy": b"5959214aa373b23a069614493160152d033ee9d10c828cf3fa5e580f850a9e05",
        "mnemonic": "铝 候 销 荡 响 序 致 已 考 床 湾 隆 罚 贝 揭 局 仪 锅 门 星 川 德 蜡 谱 谱",
        "priv_skey": "5959214aa373b23a069614493160152d033ee9d10c828cf3fa5e580f850a9e05",
        "lang": MoneroLanguages.CHINESE_SIMPLIFIED,
    },
    {
        "entropy": b"ffedd8f44ca03908c6e36ccb3946e42cf0591949c0e6abb414eca2d55821f3b8",
        "mnemonic": "胞 属 周 左 补 乡 王 任 婆 灵 植 卡 袁 属 乡 污 源 它 详 麦 毫 次 伙 乙 属",
        "priv_skey": "d0d248f62a5e6f3f9026c9caa8894f47ef591949c0e6abb414eca2d55821f308",
        "lang": MoneroLanguages.CHINESE_SIMPLIFIED,
    },
    # Dutch
    {
        "entropy": b"b12434ae4b055a6c5250725ca100f062ae1d38644cc9d3b432cf1223b25edc0b",
        "mnemonic": "larve wacht ommegaand budget puppy bombarde stoven kilsdonk stijf epileer bachelor klus tukje teisman eeneiig kluif vrucht opel galvlieg ugandees zworen afzijdig fornuis giraal fornuis",
        "priv_skey": "b12434ae4b055a6c5250725ca100f062ae1d38644cc9d3b432cf1223b25edc0b",
        "lang": MoneroLanguages.DUTCH,
    },
    {
        "entropy": b"57e816df31ef07580b698d1fa5e5804b263ae43995b6688f51e68fceecf5f9ef",
        "mnemonic": "ockhuizen essing brevet symboliek kart slordig hoeve olifant rodijk altsax creatie kneedbaar vetstaart exotherm laxeerpil lekdicht luikenaar bemiddeld oudachtig josua elburg kieviet escort dimbaar kieviet",
        "priv_skey": "6151a5c9c083068752d50236783b4f27253ae43995b6688f51e68fceecf5f90f",
        "lang": MoneroLanguages.DUTCH,
    },
    # English
    {
        "entropy": b"56be20de94b0df2a2e506059d29a7051978b377c7cc361e167715ad13c95a909",
        "mnemonic": "vials licks gulp people reorder tulips acquire cool lunar upwards recipe against ambush february shelter textbook annoyed veered getting swagger paradise total dawn duets getting",
        "priv_skey": "56be20de94b0df2a2e506059d29a7051978b377c7cc361e167715ad13c95a909",
        "lang": MoneroLanguages.ENGLISH,
    },
    {
        "entropy": b"bd47836643eec5b11da9ef5458a990800d8e107d1699fd3eeec7a95599a6bd07",
        "mnemonic": "mohawk apex jukebox rewind stacking lopped daily clue lesson eggs attire nightly ostrich elite rotate vacation pastry twofold seventh gutter quote mammal patio poker lopped",
        "priv_skey": "bd47836643eec5b11da9ef5458a990800d8e107d1699fd3eeec7a95599a6bd07",
        "lang": MoneroLanguages.ENGLISH,
    },
    # French
    {
        "entropy": b"bb37794073e5094ebbfcfa070e9254fe6094b56e7cccb094a2304c5eccccdc07",
        "mnemonic": "manger parmi tache vice ciel lingot poison filtre fuir ragot parole palissade nourrir bonheur monsieur frais tant lien groupe revue capot votre suite tibia lingot",
        "priv_skey": "bb37794073e5094ebbfcfa070e9254fe6094b56e7cccb094a2304c5eccccdc07",
        "lang": MoneroLanguages.FRENCH,
    },
    {
        "entropy": b"e9ccd9a4f6c806e938e1c163f7725417fa8c52e06b8e5a559786d6333e42c5c7",
        "mnemonic": "globe lever bout plat grave exiger foison gaufre relever samba sondage usure occuper avouer vache organe digue neuve bondir assez draguer parc faxer bavoir faxer",
        "priv_skey": "cddd5349ba232ac82c8726c087bce01cf98c52e06b8e5a559786d6333e42c507",
        "lang": MoneroLanguages.FRENCH,
    },
    # German
    {
        "entropy": b"73b4db08fab9e2fa0fb3403be207cb4f169e55e80a8ef357c283fa785eb90600",
        "mnemonic": "Vase Bezug Brosche Wohl absuchen Zufahrt Arktis Argument erfüllen Farbe Möbel Abitur Umsturz Dreieck Bitte Frachter Hobel Schwan Trost Kreuz Atlantik abrüsten Brauerei Brauerei Vase",
        "priv_skey": "73b4db08fab9e2fa0fb3403be207cb4f169e55e80a8ef357c283fa785eb90600",
        "lang": MoneroLanguages.GERMAN,
    },
    {
        "entropy": b"5e89f425c0a095191224e8a8d35d1dbc95b31a8a07942051d461f8311737b0dc",
        "mnemonic": "Galaxie einatmen gähnen Alkohol Flasche hadern Objekt Kampagne Defekt Neugier Gelübde Brandung Parka Beichte Maisbrei Gefieder Dolch Käfer Hexe Kombüse Radclub Flamenco Radtour Macht Defekt",
        "priv_skey": "55c6786d6998a6a02f2d556285adcaac94b31a8a07942051d461f8311737b00c",
        "lang": MoneroLanguages.GERMAN,
    },
    # Italian
    {
        "entropy": b"a4e7b04e91702a9b0bc841f293a0352b56546da8506ba59e48d4582451be4a00",
        "mnemonic": "credere oceano torrente parente delfino sviluppo eterno pancetta muscolo farfalla meritare rapace sgabello occhio cronaca offrire emergere valore manzo cassetta emozione malloppo fiume flacone credere",
        "priv_skey": "a4e7b04e91702a9b0bc841f293a0352b56546da8506ba59e48d4582451be4a00",
        "lang": MoneroLanguages.ITALIAN,
    },
    {
        "entropy": b"5cc50d51cdea384caa45ddaf0515616b4819b68e7399d3d1c2c91bbfc47b531e",
        "mnemonic": "fronte rinuncia arco vespaio pazienza valutare dramma diramare violino panfilo alleanza graffiti gallina aglio muovere martello amico spuntare firewall azzurro spavento maionese vigilare auto rinuncia",
        "priv_skey": "6ff117f4b28726f4d3a8e50c271b82564819b68e7399d3d1c2c91bbfc47b530e",
        "lang": MoneroLanguages.ITALIAN,
    },
    # Japanese
    {
        "entropy": b"d14ca71a3af00dc2d07e0e931154cd87770c663ee52295dd0ba570b02a2fc509",
        "mnemonic": "ことがら すあな そんかい さくら なのか せんろ そうだん てはい けんめい いちば とうし けぬき ちあん たたみ ねんれい いっそう おうふく あまど おさえる てんけん しちりん けつまつ けっせき こうすい ことがら",
        "priv_skey": "d14ca71a3af00dc2d07e0e931154cd87770c663ee52295dd0ba570b02a2fc509",
        "lang": MoneroLanguages.JAPANESE,
    },
    {
        "entropy": b"32777f0ee86390e712c3e6b10b67680658f3fd85e3a30871108fe7c6c96b9440",
        "mnemonic": "てくび ておくれ とばす ただしい うぶげ あぶる ぱんち にんにく せっぱん してき おうべい おとなしい せんか におい こくない しょうかい てんすう ぎじかがく あたりまえ かいしゃ はやい はあく ちりがみ ひこうき こくない",
        "priv_skey": "7e27a89a7ed74687b94f0826917fecb257f3fd85e3a30871108fe7c6c96b9400",
        "lang": MoneroLanguages.JAPANESE,
    },
    # Portuguese
    {
        "entropy": b"58f821d5fb425797baf1ded4ae69575f3fe313387f0e70fedc5761a2171ec207",
        "mnemonic": "louvor aglutinar suite sepultura cueiro revolvido asqueroso teutonico pejorativo seduzir seus dativo ombudsman laquear posudo manutencao caquizeiro bumerangue cipriota miau diatribe lotus rifle samurai posudo",
        "priv_skey": "58f821d5fb425797baf1ded4ae69575f3fe313387f0e70fedc5761a2171ec207",
        "lang": MoneroLanguages.PORTUGUESE,
    },
    {
        "entropy": b"0f3a7cda6dfabbca59d447cd83d2c25e5c405a787f63338bd4a665fc4922a085",
        "mnemonic": "rustico ecossistema bcrepuscular sudoriparo fixo bruxuleio pueril gourmet dacota tectonismo daquilo mavioso jota doer ovulo tatuar daguerreotipo potro acustico obcecar nitroglicerina exotico einsteiniano repuxo rustico",
        "priv_skey": "a79acdf29ae1280aa7ed8ab58e03cbb75b405a787f63338bd4a665fc4922a005",
        "lang": MoneroLanguages.PORTUGUESE,
    },
    # Russian
    {
        "entropy": b"9cfe189bf8e94853ad6670548fea81e711c7c2256b25259102692220a534770d",
        "mnemonic": "номер сигнал иметь километр уснуть герой эмоция титул взмах зыбкий крючок зацепка характер нечистый рамка кошка локоть яблоко туча слюна утка сцена джунгли жирный номер",
        "priv_skey": "9cfe189bf8e94853ad6670548fea81e711c7c2256b25259102692220a534770d",
        "lang": MoneroLanguages.RUSSIAN,
    },
    {
        "entropy": b"31d57df1d53bb6f68b68cbf66738364eaad82ea077ffe1b40942d1617ccc5f2a",
        "mnemonic": "предмет банк август инцидент халат уран сшивать утешать тысяча мечтать стыд башня сдвигать герой тонкий друг баян сфера эстрада сапог бицепс ярость хвост афера герой",
        "priv_skey": "572d9237a1759146df2edcb0aa447824aad82ea077ffe1b40942d1617ccc5f0a",
        "lang": MoneroLanguages.RUSSIAN,
    },
    # Spanish
    {
        "entropy": b"4d38dcd7e1aabe8a13a98c9fe9c4f9919351ee6ec526d32c4a2b7f81760c1005",
        "mnemonic": "hueco destino bravo farsa payaso esposa ola ciprés perico boda fútbol alegre forro escena oso gacela prensa arpa cuesta alfiler humilde cuesta fatiga finca boda",
        "priv_skey": "4d38dcd7e1aabe8a13a98c9fe9c4f9919351ee6ec526d32c4a2b7f81760c1005",
        "lang": MoneroLanguages.SPANISH,
    },
    {
        "entropy": b"6af1598b05384f66c81828e7a646421626caae0073909f222304bc3474bc7398",
        "mnemonic": "oración aries linterna canela febrero oxígeno baba remedio picar cochino gripe juvenil policía chapa chivo disco alma burro muela elixir isla juez ritmo juzgar febrero",
        "priv_skey": "157eb54618bca94d3f95732cd37d6b5a25caae0073909f222304bc3474bc7308",
        "lang": MoneroLanguages.SPANISH,
    },
]

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey",
        "exception": ValueError,
    },
    # Wrong checksum
    {
        "mnemonic": "abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abducts",
        "exception": MnemonicChecksumError,
    },
    # Not existent word
    {
        "mnemonic": "abbey abbey notexistent abbey abbey abbey abbey abbey abbey abbey abbey abbey",
        "exception": ValueError,
    },
    {
        "mnemonic": "abbey abbey notexistent abbey abbey abbey abbey abbey abbey abbey abbey abbey",
        "lang": None,
        "exception": ValueError,
    },
    # Wrong language
    {
        "mnemonic": "abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey",
        "lang": MoneroLanguages.ITALIAN,
        "exception": ValueError,
    },
]


#
# Tests
#
class MoneroMnemonicTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"]

            # Test both generating with checksum and without checksum (keys and entropy shall be the same in both cases)
            for i in range(0, 2):
                # Test mnemonic generator
                if i == 0:
                    mnemonic = MoneroMnemonicGenerator(lang).FromEntropyWithChecksum(binascii.unhexlify(test["entropy"]))
                    self.assertEqual(test["mnemonic"], mnemonic.ToStr())
                    self.assertEqual(test["mnemonic"], str(mnemonic))
                    self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
                    self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())
                else:
                    mnemonic = MoneroMnemonicGenerator(lang).FromEntropyNoChecksum(binascii.unhexlify(test["entropy"]))
                    self.assertEqual(test["mnemonic"].split(" ")[:-1], mnemonic.ToList())
                    self.assertEqual(len(test["mnemonic"].split(" ")) - 1, mnemonic.WordsCount())

                # Test mnemonic validator (language specified)
                mnemonic_validator = MoneroMnemonicValidator(lang)
                self.assertTrue(mnemonic_validator.IsValid(mnemonic))
                # Test mnemonic validator (automatic language detection)
                mnemonic_validator = MoneroMnemonicValidator()
                self.assertTrue(mnemonic_validator.IsValid(mnemonic))

                # Test decoder with no checksum (language specified)
                entropy = MoneroMnemonicDecoder(lang).Decode(mnemonic)
                self.assertEqual(test["entropy"], binascii.hexlify(entropy))
                # Test decoder with no checksum (automatic language detection)
                entropy = MoneroMnemonicDecoder().Decode(mnemonic)
                self.assertEqual(test["entropy"], binascii.hexlify(entropy))

                # Test seed generator (seed is the entropy itself for Monero)
                seed = MoneroSeedGenerator(mnemonic, lang).Generate()
                self.assertEqual(test["entropy"], binascii.hexlify(seed))

                # Test private key
                monero = Monero.FromSeed(seed)
                self.assertEqual(test["priv_skey"], monero.PrivateSpendKey().Raw().ToHex())

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        for test_bit_len in MoneroEntropyBitLen:
            # Test generator
            entropy = MoneroEntropyGenerator(test_bit_len).Generate()
            self.assertEqual(len(entropy), test_bit_len // 8)

            # Compute the expected mnemonic length
            mnemonic_len_no_chksum = (test_bit_len // 32) * 3

            # Generate mnemonic with no checksum
            mnemonic = MoneroMnemonicGenerator().FromEntropyNoChecksum(entropy)
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len_no_chksum)

            # Generate mnemonic with checksum
            mnemonic = MoneroMnemonicGenerator().FromEntropyWithChecksum(entropy)
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len_no_chksum + 1)

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        for test_bit_len in MoneroEntropyBitLen:
            self.assertRaises(ValueError, MoneroEntropyGenerator, test_bit_len - 1)
            self.assertRaises(ValueError, MoneroEntropyGenerator, test_bit_len + 1)

            # Build a dummy entropy with invalid bit length
            dummy_ent = b"\x00" * ((test_bit_len - 8) // 8)
            self.assertRaises(ValueError, MoneroMnemonicGenerator().FromEntropyWithChecksum, dummy_ent)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        for test_words_num in MoneroWordsNum:
            mnemonic = MoneroMnemonicGenerator().FromWordsNumber(test_words_num)
            self.assertEqual(mnemonic.WordsCount(), test_words_num)

    # Test construction from invalid words number
    def test_from_invalid_words_num(self):
        monero_int_words_num = [int(words_num) for words_num in MoneroWordsNum]
        for test_words_num in monero_int_words_num:
            if test_words_num - 1 not in monero_int_words_num:
                self.assertRaises(ValueError, MoneroMnemonicGenerator().FromWordsNumber, test_words_num - 1)
            if test_words_num + 1 not in monero_int_words_num:
                self.assertRaises(ValueError, MoneroMnemonicGenerator().FromWordsNumber, test_words_num + 1)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else MoneroLanguages.ENGLISH

            self.assertFalse(MoneroMnemonicValidator(lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], MoneroMnemonicValidator(lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], MoneroSeedGenerator, test["mnemonic"], lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, MoneroMnemonicGenerator, 0)
        self.assertRaises(TypeError, MoneroMnemonicValidator, 0)
        self.assertRaises(TypeError, MoneroSeedGenerator, "", 0)
