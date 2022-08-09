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
    Bip39EntropyBitLen, Bip39EntropyGenerator, Bip39Languages, Bip39MnemonicDecoder, Bip39MnemonicGenerator,
    Bip39MnemonicValidator, Bip39SeedGenerator, Bip39WordsNum, MnemonicChecksumError
)


# Tests from BIP39 page
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
TEST_VECT = [
    #
    # Basic 12-words
    #
    {
        "entropy": b"00000000000000000000000000000000",
        "entropy_chksum": b"0000000000000000000000000000000003",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed": b"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    },
    {
        "entropy": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "entropy_chksum": b"07f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f8",
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "seed": b"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    },
    {
        "entropy": b"80808080808080808080808080808080",
        "entropy_chksum": b"0808080808080808080808080808080804",
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "seed": b"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    },
    {
        "entropy": b"ffffffffffffffffffffffffffffffff",
        "entropy_chksum": b"0ffffffffffffffffffffffffffffffff5",
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "seed": b"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    },

    #
    # Basic 18-words
    #
    {
        "entropy": b"000000000000000000000000000000000000000000000000",
        "entropy_chksum": b"00000000000000000000000000000000000000000000000027",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "seed": b"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    },
    {
        "entropy": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "entropy_chksum": b"1fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd9",
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "seed": b"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
    },
    {
        "entropy": b"808080808080808080808080808080808080808080808080",
        "entropy_chksum": b"2020202020202020202020202020202020202020202020203c",
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "seed": b"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    },
    {
        "entropy": b"ffffffffffffffffffffffffffffffffffffffffffffffff",
        "entropy_chksum": b"3fffffffffffffffffffffffffffffffffffffffffffffffd1",
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "seed": b"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
    },

    #
    # Basic 24-words
    #
    {
        "entropy": b"0000000000000000000000000000000000000000000000000000000000000000",
        "entropy_chksum": b"000000000000000000000000000000000000000000000000000000000000000066",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "seed": b"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    },
    {
        "entropy": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "entropy_chksum": b"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f17",
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "seed": b"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    },
    {
        "entropy": b"8080808080808080808080808080808080808080808080808080808080808080",
        "entropy_chksum": b"8080808080808080808080808080808080808080808080808080808080808080bd",
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "seed": b"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    },
    {
        "entropy": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "entropy_chksum": b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaf",
        "mnemonic": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "seed": b"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    },

    #
    # Various
    #
    {
        "entropy": b"9e885d952ad362caeb4efe34a8e91bd2",
        "entropy_chksum": b"09e885d952ad362caeb4efe34a8e91bd21",
        "mnemonic": "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "seed": b"274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    },
    {
        "entropy": b"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "entropy_chksum": b"19842c9659f3732a75661d7d72d42c3a9d50ccc461a7a4c2d2",
        "mnemonic": "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "seed": b"628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
    },
    {
        "entropy": b"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "entropy_chksum": b"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c00",
        "mnemonic": "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "seed": b"64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    },

    {
        "entropy": b"c0ba5a8e914111210f2bd131f3d5e08d",
        "entropy_chksum": b"0c0ba5a8e914111210f2bd131f3d5e08d0",
        "mnemonic": "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "seed": b"ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
    },
    {
        "entropy": b"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "entropy_chksum": b"1b66f87b9baf49e8960456ab666dcc5ee7234a2db5d90c70da",
        "mnemonic": "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "seed": b"fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
    },
    {
        "entropy": b"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "entropy_chksum": b"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863a9",
        "mnemonic": "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "seed": b"72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    },

    {
        "entropy": b"23db8160a31d3e0dca3688ed941adbf3",
        "entropy_chksum": b"023db8160a31d3e0dca3688ed941adbf38",
        "mnemonic": "cat swing flag economy stadium alone churn speed unique patch report train",
        "seed": b"deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
    },
    {
        "entropy": b"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "entropy_chksum": b"2065e9291fc1097ebaa9a77baf01728a70296d731db3ab300a",
        "mnemonic": "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "seed": b"4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
    },
    {
        "entropy": b"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "entropy_chksum": b"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efada2",
        "mnemonic": "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "seed": b"26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
    },

    {
        "entropy": b"f30f8c1da665478f49b001d94c5fc452",
        "entropy_chksum": b"0f30f8c1da665478f49b001d94c5fc4522",
        "mnemonic": "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "seed": b"2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
    },
    {
        "entropy": b"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "entropy_chksum": b"3043b08370f367d94b1feb0bc48c3de8f20a0e26850e4bc162",
        "mnemonic": "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "seed": b"7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
    },
    {
        "entropy": b"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "entropy_chksum": b"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f69",
        "mnemonic": "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "seed": b"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    },

    #
    # Different languages (generated and checked with other tools)
    #

    # Chinese (simplified)
    {
        "entropy": b"4af203a39228787182365db8625ef85c",
        "mnemonic": "犯 宝 亭 术 圈 斯 度 鸭 允 但 荒 兼",
        "seed": b"873a8af2f9a181e6006f5b47b76d90668edd217271276dcc42e09aeed410f9c3037861e8f45d7fd977dd47b27ff59cb99f69464af34db0696979b2cab60f6641",
        "lang": Bip39Languages.CHINESE_SIMPLIFIED,
    },
    {
        "entropy": b"c728f71b2169073ff18c0a7cc13b7dcc026ed301afd0f0b359ae9db27e41d45d",
        "mnemonic": "竞 爱 洛 李 闻 冰 瓷 敢 归 高 胀 嘴 切 伯 后 嫂 浩 臣 乐 京 场 光 跑 碧",
        "seed": b"e31b8769b7e95b703f18d51f0dbb02d160f66d0736e9c450491402b3f86a02947ad1cc26695dfa96146ab0f709ba0df581d52289fbdca8b0e0df94e9ef33e9d6",
        "lang": Bip39Languages.CHINESE_SIMPLIFIED,
    },
    # Chinese (traditional)
    {
        "entropy": b"3546f07366d9451fff7e90ec48a48ad6",
        "mnemonic": "酸 劃 別 冒 耕 頓 餓 輔 烷 另 東 幸",
        "seed": b"d863e03468ee820d51bb2d3965c4ec6788343811a3de88b962aa924ac3c8e329204d865540757e9b5884bc1f8c99c2a266992e764cb4cadb6ef6f55dfa86a7b4",
        "lang": Bip39Languages.CHINESE_TRADITIONAL,
    },
    {
        "entropy": b"5c44ac4fcb2bf886df37a5391dac7b08bd19610c700580663462146b7557b14f",
        "mnemonic": "衛 權 變 煉 簽 輪 歸 纜 查 撒 西 正 錫 獎 連 了 腦 驗 入 萬 仲 窮 迷 漂",
        "seed": b"d817a3dcf7365911d7eb7a28f3cd6c833462100cbfc4f3db3b54beb03ed13170bb7f990f2589c8ab0fb4aaf5a561a4544556f5260a0ecedf252c4c42861f11a0",
        "lang": Bip39Languages.CHINESE_TRADITIONAL,
    },
    # Czech
    {
        "entropy": b"0cc43525e0289632d208c4b45b0d912c",
        "mnemonic": "branka dorost klam slanina omezit cuketa kazeta cizost rozchod tvaroh majetek kyvadlo",
        "seed": b"6f34c0375358ff4188cf884e8dbb3b45738afe9fd7389b700f3bad4781c6e36db657f748d5a10abb8d30f36a0f067401453eb75cb8e9758394b53d74448b7932",
        "lang": Bip39Languages.CZECH,
    },
    {
        "entropy": b"13c1b202721c14e9390b093dec53ce898028be41a8be10d83178b2139d331731",
        "mnemonic": "chichot bronz obvinit vidle slina naposled vidle lomcovat invalida lstivost zamezit chalupa astma lihovina bazilika cinkot bzukot slon letokruh mahagon hrnek plevel lehce facka",
        "seed": b"b1c4419f57696d40e6a764490ba62a1eb3722c5aa3636a168700a624fff6420ba10277d4c0d8a0989126af30bd939cce8acd7bd305f9d6757377fd8fbdae446a",
        "lang": Bip39Languages.CZECH,
    },
    # French
    {
        "entropy": b"c4cf0ca40669a21673d3419b9bce0489",
        "mnemonic": "pupitre hangar capable anaphore mérite ambigu revivre fixer miette sodium inexact asticot",
        "seed": b"73bc4755506335d59cc7ffd493465a16e09a0cce83dcde8b0d2a96b171ec1e05ceea2886f63936b7229ccb90c464ca58ebc2b024ec0d5505fe7b0d1ec2bdf419",
        "lang": Bip39Languages.FRENCH,
    },
    {
        "entropy": b"639b3b85d452eaa61ddeeebb7699792483c9b75d0020311d0002e2b13bf0ed01",
        "mnemonic": "fatigue semaine souvenir obliger chausson encoche guitare sismique plateau peigne éviter donjon cuisine sésame gouffre acompte cigare tarif aborder querelle astre venimeux patience cascade",
        "seed": b"02440d6ea198766fe10c7e5a532fcbe231024bb09ad3dd4665dcbd3427911228e6f1ebce9e21b26172e0a4cd172a37bdc41cdc26c9f6dd97e91c0cdfc5e0fa11",
        "lang": Bip39Languages.FRENCH,
    },
    # Italian
    {
        "entropy": b"1f3816778bbb384fa7dab64f593ec7df",
        "mnemonic": "bosco sarto perplesso baccano ribadire cassone piacere frassino favoloso seme replica sagoma",
        "seed": b"332e7e798088280ae79534de319252f6f8ed357ee7dc1c2aa674cb46546184f25367c9cd1bedbf6a10b8ba2306a33dc13828c8629967e1bd26a952545b769969",
        "lang": Bip39Languages.ITALIAN,
    },
    {
        "entropy": b"e12e14deab85bcbafc561e44d50f96d71357aa08b1251a8abe392fa1e560465d",
        "mnemonic": "svolta lentezza davvero freccetta gatto gergo unitario scambiare eluso pretesto tesserato ramingo cuculo solvente bussola campale bava foro odierno giurato bisturi recinto barca rinnovo",
        "seed": b"79558674b80227b7ec92567744cbbf91fd97ec26bf266d1b3defd2304ffce4ad4e11acc072ecf5e820cb8211f399ac2584e15e3ee8b580e7abe8171b451f8a81",
        "lang": Bip39Languages.ITALIAN,
    },
    # Korean
    {
        "entropy": b"7cf050d2a257004f26decf7d100c1ffd",
        "mnemonic": "신규 아시아 동화책 민주 솔직히 넥타이 요금 출입 신념 실험 거품 환영",
        "seed": b"64e91f1ca49a1463905da6ec21a00b44c24f6fc3b6ce9ec18a1f277f6f17f01ecd70c29ac20751f50eea954d62e74616178cf10a18dd3d5aa767fcad2cd15f9a",
        "lang": Bip39Languages.KOREAN,
    },
    {
        "entropy": b"2e59cfc5e2466699703543185fdad758bf0095146d8616eeb53fb935b977c7d9",
        "mnemonic": "담임 짜증 한여름 주말 서적 백색 제출 이틀 국가 흑인 재산 작업 한꺼번에 방면 보름 자존심 구름 스스로 변명 수업 비용 점수 기념 대합실",
        "seed": b"6f76a73fb8d7124e5b893fa752df2fa9f1cca7178524f9f8ca2f7c2674c6967eb5772f8b7645b45d9a0ecff2ff039582b31614e32603e395c6b33b3736c1cc7e",
        "lang": Bip39Languages.KOREAN,
    },
    # Portuguese
    {
        "entropy": b"502f2e4fdebd715a7b04f3fd28069e50",
        "mnemonic": "dominado guaxinim lotado piscar sadio olaria tinteiro mexer voador cortejo neural moita",
        "seed": b"7fa6942c80ac82e1fbbd8bfcd1d71a9a3a7fdd8c76a6631c8bc1adf84af75364267ec7e63e8b2e922e4f8a89041f0293490374b0999921385503148eeb8df8cd",
        "lang": Bip39Languages.PORTUGUESE,
    },
    {
        "entropy": b"e1257e7d2c2d5d13f69ba62693e7c4efd4e4084f2747af3a6a5e6c316ce24e62",
        "mnemonic": "soprano cacau milhar enquanto rugido juiz secar girino bocado milenar trilogia socorro discreta aclamar coluna teclado orar robalo manada saltar arroba garimpo clareza esgrima",
        "seed": b"06bcf33e49ba7055bf2c405e2921b76ecc9348998612fb383ab294c87d0791bdfc6451091ff29642bdb2cdffa90cf478e731223f42ca5f9c06777ea6a7c25e33",
        "lang": Bip39Languages.PORTUGUESE,
    },
    # Spanish
    {
        "entropy": b"72754293ddabb5286e683ab657636637",
        "mnemonic": "inerte panal órbita proa proa mover potro ajeno pleno prisión sodio humilde",
        "seed": b"fb88d495839e5a0a9f03048349e016cd0d2f1add2625da9911b5679c0927ebe364470c0675af47c46ccf94dc2e243d62c00e1c5687144177f37cf30ec356fb7d",
        "lang": Bip39Languages.SPANISH,
    },
    {
        "entropy": b"0a7a0e7056dd570d3031f11c1f77b6be79d65794263344e11e1e3c11c7fd1886",
        "mnemonic": "alto sagrado nota peatón señal maldad radical curar barco visor trauma legión nueve carro esquí reloj disco alfiler mando júpiter báscula yeso gastar rígido",
        "seed": b"b1f69660a6defbee34a85dce645858da424e5c481f9b61ec9758fbd5d986ca95eb790f0fd0878356c7f79d3b85ca030d45e85fe680987429f27b8d2fde3e41a6",
        "lang": Bip39Languages.SPANISH,
    },
]

# Tests passphrase
TEST_PASSPHRASE = "TREZOR"

# Tests for invalid mnemonics
TEST_VECT_MNEMONIC_INVALID = [
    # Wrong length
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "exception": ValueError,
    },
    # Wrong checksum
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon any",
        "exception": MnemonicChecksumError,
    },
    # Not existent word
    {
        "mnemonic": "abandon abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon about",
        "exception": ValueError,
    },
    {
        "mnemonic": "abandon abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon about",
        "lang": None,
        "exception": ValueError,
    },
    # Wrong language
    {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "lang": Bip39Languages.ITALIAN,
        "exception": ValueError,
    },
]


#
# Tests
#
class Bip39Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            lang = test["lang"] if "lang" in test else Bip39Languages.ENGLISH

            # Test mnemonic generator
            mnemonic = Bip39MnemonicGenerator(lang).FromEntropy(binascii.unhexlify(test["entropy"]))

            self.assertEqual(test["mnemonic"], mnemonic.ToStr())
            self.assertEqual(test["mnemonic"], str(mnemonic))
            self.assertEqual(test["mnemonic"].split(" "), mnemonic.ToList())
            self.assertEqual(len(test["mnemonic"].split(" ")), mnemonic.WordsCount())

            # Test mnemonic validator (language specified)
            mnemonic_validator = Bip39MnemonicValidator(lang)
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))
            # Test mnemonic validator (automatic language detection)
            mnemonic_validator = Bip39MnemonicValidator()
            self.assertTrue(mnemonic_validator.IsValid(mnemonic))

            # Test decoder (language specified)
            entropy = Bip39MnemonicDecoder(lang).Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))
            # Test decoder (automatic language detection)
            entropy = Bip39MnemonicDecoder().Decode(mnemonic)
            self.assertEqual(test["entropy"], binascii.hexlify(entropy))

            # Test decoder with checksum
            if "entropy_chksum" in test:
                entropy = Bip39MnemonicDecoder(lang).DecodeWithChecksum(mnemonic)
                self.assertEqual(test["entropy_chksum"], binascii.hexlify(entropy))

                entropy = Bip39MnemonicDecoder().DecodeWithChecksum(mnemonic)
                self.assertEqual(test["entropy_chksum"], binascii.hexlify(entropy))

            # Test seed generator
            seed = Bip39SeedGenerator(mnemonic, lang).Generate(TEST_PASSPHRASE)
            self.assertEqual(test["seed"], binascii.hexlify(seed))

    # Test entropy generator and construction from valid entropy bit lengths
    def test_entropy_valid_bitlen(self):
        for test_bit_len in Bip39EntropyBitLen:
            # Test generator
            entropy = Bip39EntropyGenerator(test_bit_len).Generate()
            self.assertEqual(len(entropy), test_bit_len // 8)

            # Generate mnemonic
            mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy)
            # Compute the expected mnemonic length
            mnemonic_len = (test_bit_len + (test_bit_len // 32)) // 11
            # Test generated mnemonic length
            self.assertEqual(mnemonic.WordsCount(), mnemonic_len)

    # Test entropy generator and construction from invalid entropy bit lengths
    def test_entropy_invalid_bitlen(self):
        for test_bit_len in Bip39EntropyBitLen:
            self.assertRaises(ValueError, Bip39EntropyGenerator, test_bit_len - 1)
            self.assertRaises(ValueError, Bip39EntropyGenerator, test_bit_len + 1)

            # Build a dummy entropy with invalid bit length
            dummy_ent = b"\x00" * ((test_bit_len - 8) // 8)
            self.assertRaises(ValueError, Bip39MnemonicGenerator().FromEntropy, dummy_ent)

    # Test construction from valid words number
    def test_from_valid_words_num(self):
        for test_words_num in Bip39WordsNum:
            mnemonic = Bip39MnemonicGenerator().FromWordsNumber(test_words_num)
            self.assertEqual(mnemonic.WordsCount(), test_words_num)

    # Test construction from invalid words number
    def test_from_invalid_words_num(self):
        for test_words_num in Bip39WordsNum:
            self.assertRaises(ValueError, Bip39MnemonicGenerator().FromWordsNumber, test_words_num - 1)
            self.assertRaises(ValueError, Bip39MnemonicGenerator().FromWordsNumber, test_words_num + 1)

    # Tests invalid mnemonic
    def test_invalid_mnemonic(self):
        for test in TEST_VECT_MNEMONIC_INVALID:
            lang = test["lang"] if "lang" in test else Bip39Languages.ENGLISH

            self.assertFalse(Bip39MnemonicValidator(lang).IsValid(test["mnemonic"]))
            self.assertRaises(test["exception"], Bip39MnemonicValidator(lang).Validate, test["mnemonic"])
            self.assertRaises(test["exception"], Bip39SeedGenerator, test["mnemonic"], lang)

    # Tests invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, Bip39MnemonicGenerator, 0)
        self.assertRaises(TypeError, Bip39MnemonicValidator, 0)
        self.assertRaises(TypeError, Bip39SeedGenerator, "", 0)
