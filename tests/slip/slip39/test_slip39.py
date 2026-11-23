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
import dataclasses
import itertools
import unittest

from bip_utils import (
    Bip32Slip10Secp256k1,
    MnemonicChecksumError,
    Slip39Languages,
    Slip39Mnemonic,
    Slip39MnemonicDecoder,
    Slip39MnemonicEncoder,
    Slip39MnemonicGenerator,
    Slip39MnemonicValidator,
    Slip39SeedGenerator,
    Slip39Share,
    Slip39WordsNum,
)
from bip_utils.slip.slip39.slip39_mnemonic_utils import Slip39WordsListGetter
from bip_utils.slip.slip39.slip39_shamir import Slip39Gf256, Slip39Shamir


# Passphrase used by all valid official test vectors
TEST_VECT_PASSPHRASE = "TREZOR"


# Official SLIP39 test vectors (passphrase: TREZOR)
# https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json
TEST_VECT = [
    {
        "desc": "1. Valid mnemonic without sharing (128 bits)",
        "mnemonics": [
            "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard",
        ],
        "master_secret": b"bb54aac4b89dc868ba37d9cc21b2cece",
        "xprv": "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ",
    },
    {
        "desc": "2. Mnemonic with invalid checksum (128 bits)",
        "mnemonics": [
            "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "3. Mnemonic with invalid padding (128 bits)",
        "mnemonics": [
            "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "4. Basic sharing 2-of-3 (128 bits)",
        "mnemonics": [
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
            "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking",
        ],
        "master_secret": b"b43ceb7e57a0ea8766221624d01b0864",
        "xprv": "xprv9s21ZrQH143K2nNuAbfWPHBtfiSCS14XQgb3otW4pX655q58EEZeC8zmjEUwucBu9dPnxdpbZLCn57yx45RBkwJHnwHFjZK4XPJ8SyeYjYg",
    },
    {
        "desc": "5. Basic sharing 2-of-3 (128 bits)",
        "mnemonics": [
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "6. Mnemonics with different identifiers (128 bits)",
        "mnemonics": [
            "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
            "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "7. Mnemonics with different iteration exponents (128 bits)",
        "mnemonics": [
            "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
            "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "8. Mnemonics with mismatching group thresholds (128 bits)",
        "mnemonics": [
            "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
            "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
            "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "9. Mnemonics with mismatching group counts (128 bits)",
        "mnemonics": [
            "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
            "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "10. Mnemonics with greater group threshold than group counts (128 bits)",
        "mnemonics": [
            "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
            "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
            "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "11. Mnemonics with duplicate member indices (128 bits)",
        "mnemonics": [
            "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
            "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "12. Mnemonics with mismatching member thresholds (128 bits)",
        "mnemonics": [
            "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
            "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "13. Mnemonics giving an invalid digest (128 bits)",
        "mnemonics": [
            "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
            "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "14. Insufficient number of groups (128 bits, case 1)",
        "mnemonics": [
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "15. Insufficient number of groups (128 bits, case 2)",
        "mnemonics": [
            "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "16. Threshold number of groups, but insufficient number of members in one group (128 bits)",
        "mnemonics": [
            "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "17. Threshold number of groups and members in each group (128 bits, case 1)",
        "mnemonics": [
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
            "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
            "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
            "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
        ],
        "master_secret": b"7c3397a292a5941682d7a4ae2d898d11",
        "xprv": "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV",
    },
    {
        "desc": "18. Threshold number of groups and members in each group (128 bits, case 2)",
        "mnemonics": [
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
            "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
        ],
        "master_secret": b"7c3397a292a5941682d7a4ae2d898d11",
        "xprv": "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV",
    },
    {
        "desc": "19. Threshold number of groups and members in each group (128 bits, case 3)",
        "mnemonics": [
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
            "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market",
        ],
        "master_secret": b"7c3397a292a5941682d7a4ae2d898d11",
        "xprv": "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV",
    },
    {
        "desc": "20. Valid mnemonic without sharing (256 bits)",
        "mnemonics": [
            "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck",
        ],
        "master_secret": b"989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92",
        "xprv": "xprv9s21ZrQH143K41mrxxMT2FpiheQ9MFNmWVK4tvX2s28KLZAhuXWskJCKVRQprq9TnjzzzEYePpt764csiCxTt22xwGPiRmUjYUUdjaut8RM",
    },
    {
        "desc": "21. Mnemonic with invalid checksum (256 bits)",
        "mnemonics": [
            "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "22. Mnemonic with invalid padding (256 bits)",
        "mnemonics": [
            "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "23. Basic sharing 2-of-3 (256 bits)",
        "mnemonics": [
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
            "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade",
        ],
        "master_secret": b"c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae",
        "xprv": "xprv9s21ZrQH143K3a4GRMgK8WnawupkwkP6gyHxRsXnMsYPTPH21fWwNcAytijtfyftqNfiaY8LgQVdBQvHZ9FBvtwdjC7LCYxjYruJFuLzyMQ",
    },
    {
        "desc": "24. Basic sharing 2-of-3 (256 bits)",
        "mnemonics": [
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "25. Mnemonics with different identifiers (256 bits)",
        "mnemonics": [
            "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
            "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "26. Mnemonics with different iteration exponents (256 bits)",
        "mnemonics": [
            "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
            "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "27. Mnemonics with mismatching group thresholds (256 bits)",
        "mnemonics": [
            "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
            "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
            "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "28. Mnemonics with mismatching group counts (256 bits)",
        "mnemonics": [
            "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
            "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "29. Mnemonics with greater group threshold than group counts (256 bits)",
        "mnemonics": [
            "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
            "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
            "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "30. Mnemonics with duplicate member indices (256 bits)",
        "mnemonics": [
            "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
            "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "31. Mnemonics with mismatching member thresholds (256 bits)",
        "mnemonics": [
            "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
            "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "32. Mnemonics giving an invalid digest (256 bits)",
        "mnemonics": [
            "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
            "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "33. Insufficient number of groups (256 bits, case 1)",
        "mnemonics": [
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "34. Insufficient number of groups (256 bits, case 2)",
        "mnemonics": [
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "35. Threshold number of groups, but insufficient number of members in one group (256 bits)",
        "mnemonics": [
            "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "36. Threshold number of groups and members in each group (256 bits, case 1)",
        "mnemonics": [
            "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
            "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
            "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
        ],
        "master_secret": b"5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
        "xprv": "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c",
    },
    {
        "desc": "37. Threshold number of groups and members in each group (256 bits, case 2)",
        "mnemonics": [
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
            "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",
        ],
        "master_secret": b"5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
        "xprv": "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c",
    },
    {
        "desc": "38. Threshold number of groups and members in each group (256 bits, case 3)",
        "mnemonics": [
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
            "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs",
        ],
        "master_secret": b"5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
        "xprv": "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c",
    },
    {
        "desc": "39. Mnemonic with insufficient length",
        "mnemonics": [
            "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "40. Mnemonic with invalid master secret length",
        "mnemonics": [
            "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter",
        ],
        "master_secret": b"",
        "xprv": "",
    },
    {
        "desc": "41. Valid mnemonics which can detect some errors in modular arithmetic",
        "mnemonics": [
            "herald flea academic cage avoid space trend estate dryer hairy evoke eyebrow improve airline artwork garlic premium duration prevent oven",
            "herald flea academic client blue skunk class goat luxury deny presence impulse graduate clay join blanket bulge survive dish necklace",
            "herald flea academic acne advance fused brother frozen broken game ranked ajar already believe check install theory angry exercise adult",
        ],
        "master_secret": b"ad6f2ad8b59bbbaa01369b9006208d9a",
        "xprv": "xprv9s21ZrQH143K2R4HJxcG1eUsudvHM753BZ9vaGkpYCoeEhCQx147C5qEcupPHxcXYfdYMwJmsKXrHDhtEwutxTTvFzdDCZVQwHneeQH8ioH",
    },
    {
        "desc": "42. Valid extendable mnemonic without sharing (128 bits)",
        "mnemonics": [
            "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn",
        ],
        "master_secret": b"1679b4516e0ee5954351d288a838f45e",
        "xprv": "xprv9s21ZrQH143K2w6eTpQnB73CU8Qrhg6gN3D66Jr16n5uorwoV7CwxQ5DofRPyok5DyRg4Q3BfHfCgJFk3boNRPPt1vEW1ENj2QckzVLQFXu",
    },
    {
        "desc": "43. Extendable basic sharing 2-of-3 (128 bits)",
        "mnemonics": [
            "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish",
            "enemy favorite academic always academic sniff script carpet romp kind promise scatter center unfair training emphasis evening belong fake enforce",
        ],
        "master_secret": b"48b1a4b80b8c209ad42c33672bdaa428",
        "xprv": "xprv9s21ZrQH143K4FS1qQdXYAFVAHiSAnjj21YAKGh2CqUPJ2yQhMmYGT4e5a2tyGLiVsRgTEvajXkxhg92zJ8zmWZas9LguQWz7WZShfJg6RS",
    },
    {
        "desc": "44. Valid extendable mnemonic without sharing (256 bits)",
        "mnemonics": [
            "impulse calcium academic academic alcohol sugar lyrics pajamas column facility finance tension extend space birthday rainbow swimming purple syndrome facility trial warn duration snapshot shadow hormone rhyme public spine counter easy hawk album",
        ],
        "master_secret": b"8340611602fe91af634a5f4608377b5235fa2d757c51d720c0c7656249a3035f",
        "xprv": "xprv9s21ZrQH143K2yJ7S8bXMiGqp1fySH8RLeFQKQmqfmmLTRwWmAYkpUcWz6M42oGoFMJRENmvsGQmunWTdizsi8v8fku8gpbVvYSiCYJTF1Y",
    },
    {
        "desc": "45. Extendable basic sharing 2-of-3 (256 bits)",
        "mnemonics": [
            "western apart academic always artist resident briefing sugar woman oven coding club ajar merit pecan answer prisoner artist fraction amount desktop mild false necklace muscle photo wealthy alpha category unwrap spew losing making",
            "western apart academic acid answer ancient auction flip image penalty oasis beaver multiple thunder problem switch alive heat inherit superior teaspoon explain blanket pencil numb lend punish endless aunt garlic humidity kidney observe",
        ],
        "master_secret": b"8dc652d6d6cd370d8c963141f6d79ba440300f25c467302c1d966bff8f62300d",
        "xprv": "xprv9s21ZrQH143K2eFW2zmu3aayWWd6MJZBG7RebW35fiKcoCZ6jFi6U5gzffB9McDdiKTecUtRqJH9GzueCXiQK1LaQXdgthS8DgWfC8Uu3z7",
    },
]

# Indexes of vectors failing because of a checksum error
TEST_VECT_CHKSUM_ERR_IDX = [1, 20]

# Decoded shares of some vectors
TEST_VECT_DECODED = [
    # 1. Valid mnemonic without sharing (128 bits)
    {
        "mnemonic": TEST_VECT[0]["mnemonics"][0],
        "share": Slip39Share(
            identifier=7945,
            extendable=False,
            iteration_exponent=0,
            group_index=0,
            group_threshold=1,
            group_count=1,
            member_index=0,
            member_threshold=1,
            value=binascii.unhexlify(b"11bc609d21747c49ba78c0701293e417"),
        ),
    },
    # 43. Extendable basic sharing 2-of-3 (128 bits)
    {
        "mnemonic": TEST_VECT[42]["mnemonics"][0],
        "share": Slip39Share(
            identifier=9066,
            extendable=True,
            iteration_exponent=0,
            group_index=0,
            group_threshold=1,
            group_count=1,
            member_index=0,
            member_threshold=2,
            value=binascii.unhexlify(b"a5a69aa82af0f8068a01d8e8c095ddf3"),
        ),
    },
]

# Valid share used as a base for invalid ones
TEST_SHARE = TEST_VECT_DECODED[0]["share"]

# Invalid shares for encoding
TEST_ENCODE_INVALID_SHARES = [
    dataclasses.replace(TEST_SHARE, identifier=-1),
    dataclasses.replace(TEST_SHARE, identifier=2 ** 15),
    dataclasses.replace(TEST_SHARE, iteration_exponent=-1),
    dataclasses.replace(TEST_SHARE, iteration_exponent=16),
    dataclasses.replace(TEST_SHARE, group_threshold=0),
    dataclasses.replace(TEST_SHARE, group_threshold=2, group_count=1),
    dataclasses.replace(TEST_SHARE, group_threshold=1, group_count=17),
    dataclasses.replace(TEST_SHARE, group_index=-1),
    dataclasses.replace(TEST_SHARE, group_index=1, group_count=1),
    dataclasses.replace(TEST_SHARE, member_threshold=0),
    dataclasses.replace(TEST_SHARE, member_threshold=17),
    dataclasses.replace(TEST_SHARE, member_index=-1),
    dataclasses.replace(TEST_SHARE, member_index=16),
    dataclasses.replace(TEST_SHARE, value=b"\x00" * 14),
    dataclasses.replace(TEST_SHARE, value=b"\x00" * 17),
]

# Invalid generator parameters
TEST_GENERATOR_INVALID_PARAMS = [
    # No group
    {"group_threshold": 1, "groups": []},
    # Too many groups
    {"group_threshold": 1, "groups": [(1, 1)] * 17},
    # Group threshold out of range
    {"group_threshold": 0, "groups": [(1, 1)]},
    {"group_threshold": 3, "groups": [(1, 1), (1, 1)]},
    # Member threshold out of range
    {"group_threshold": 1, "groups": [(0, 1)]},
    {"group_threshold": 1, "groups": [(3, 2)]},
    # Member count out of range
    {"group_threshold": 1, "groups": [(2, 17)]},
    # Member threshold 1 with more members
    {"group_threshold": 1, "groups": [(1, 2)]},
    # Iteration exponent out of range
    {"groups": [(1, 1)], "iteration_exponent": -1},
    {"groups": [(1, 1)], "iteration_exponent": 16},
]

# Invalid mnemonics for decoding/validation
TEST_DECODE_INVALID_MNEMONICS = [
    # Invalid word
    "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode "
    "duke ajar critical decision notaword",
    # Too short (19 words)
    "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode "
    "duke ajar critical decision",
    # Invalid length (21 words)
    TEST_VECT[0]["mnemonics"][0] + " academic",
]


#
# Tests
#
class Slip39Tests(unittest.TestCase):
    # Test official vectors
    def test_vectors(self):
        for i, test in enumerate(TEST_VECT):
            if test["master_secret"]:
                seed_gen = Slip39SeedGenerator(test["mnemonics"])
                seed = seed_gen.Generate(TEST_VECT_PASSPHRASE)

                self.assertEqual(test["master_secret"], binascii.hexlify(seed), test["desc"])
                self.assertEqual(test["xprv"], Bip32Slip10Secp256k1.FromSeed(seed).PrivateKey().ToExtended())
                # Using Mnemonic objects
                seed_gen = Slip39SeedGenerator([Slip39Mnemonic.FromString(m) for m in test["mnemonics"]])
                self.assertEqual(seed, seed_gen.Generate(TEST_VECT_PASSPHRASE))
            else:
                exc = MnemonicChecksumError if i in TEST_VECT_CHKSUM_ERR_IDX else ValueError
                self.assertRaises(exc, Slip39SeedGenerator, test["mnemonics"])

    # Test decoding and encoding
    def test_decode_encode(self):
        decoder = Slip39MnemonicDecoder()
        encoder = Slip39MnemonicEncoder()

        for test in TEST_VECT_DECODED:
            self.assertEqual(test["share"], decoder.Decode(test["mnemonic"]))
            self.assertEqual(test["mnemonic"], encoder.Encode(test["share"]).ToStr())

        # Encoding back all the shares of the valid vectors shall result in the same mnemonics
        for test in TEST_VECT:
            if test["master_secret"]:
                for mnemonic in test["mnemonics"]:
                    self.assertEqual(mnemonic, encoder.Encode(decoder.Decode(mnemonic)).ToStr())

        # Mnemonic is normalized
        self.assertEqual(TEST_SHARE, decoder.Decode(TEST_VECT_DECODED[0]["mnemonic"].upper()))
        self.assertEqual(TEST_SHARE, decoder.Decode("  " + TEST_VECT_DECODED[0]["mnemonic"].replace(" ", "\n  ")))

    # Test invalid encoding
    def test_invalid_encode(self):
        encoder = Slip39MnemonicEncoder()
        for share in TEST_ENCODE_INVALID_SHARES:
            self.assertRaises(ValueError, encoder.Encode, share)

    # Test invalid decoding
    def test_invalid_decode(self):
        decoder = Slip39MnemonicDecoder()
        for mnemonic in TEST_DECODE_INVALID_MNEMONICS:
            self.assertRaises(ValueError, decoder.Decode, mnemonic)
        self.assertRaises(MnemonicChecksumError, decoder.Decode, TEST_VECT[1]["mnemonics"][0])
        self.assertRaises(ValueError, decoder.Decode, TEST_VECT[2]["mnemonics"][0])

    # Test validator
    def test_validator(self):
        validator = Slip39MnemonicValidator()

        for test in TEST_VECT:
            if test["master_secret"]:
                for mnemonic in test["mnemonics"]:
                    self.assertTrue(validator.IsValid(mnemonic))
                    validator.Validate(mnemonic)

        for mnemonic in TEST_DECODE_INVALID_MNEMONICS + [TEST_VECT[2]["mnemonics"][0]]:
            self.assertFalse(validator.IsValid(mnemonic))
            self.assertRaises(ValueError, validator.Validate, mnemonic)
        self.assertFalse(validator.IsValid(TEST_VECT[1]["mnemonics"][0]))
        self.assertRaises(MnemonicChecksumError, validator.Validate, TEST_VECT[1]["mnemonics"][0])

    # Test generation from master secret and recovery with all combinations of shares
    def test_generate_and_recover(self):
        group_threshold = 2
        groups = [(1, 1), (2, 3), (3, 5)]
        passphrase = "Test passphrase !~"

        for extendable in (True, False):
            for master_secret in (bytes(range(16)), bytes(range(32)), bytes(range(64))):
                mnemonics = Slip39MnemonicGenerator(group_threshold,
                                                    groups,
                                                    extendable=extendable,
                                                    iteration_exponent=0).FromMasterSecret(master_secret, passphrase)

                # Check shares
                self.assertEqual(len(groups), len(mnemonics))
                shares = [[Slip39MnemonicDecoder().Decode(m) for m in group] for group in mnemonics]
                identifier = shares[0][0].identifier
                for group_idx, (group_shares, (member_threshold, member_count)) in enumerate(zip(shares, groups)):
                    self.assertEqual(member_count, len(group_shares))
                    for member_idx, share in enumerate(group_shares):
                        self.assertEqual(identifier, share.identifier)
                        self.assertEqual(extendable, share.extendable)
                        self.assertEqual(0, share.iteration_exponent)
                        self.assertEqual(group_idx, share.group_index)
                        self.assertEqual(group_threshold, share.group_threshold)
                        self.assertEqual(len(groups), share.group_count)
                        self.assertEqual(member_idx, share.member_index)
                        self.assertEqual(member_threshold, share.member_threshold)
                        self.assertEqual(len(master_secret), len(share.value))

                # Recover with any pair of groups and any threshold subset of members
                for group_idx_1, group_idx_2 in itertools.combinations(range(len(groups)), 2):
                    for members_1 in itertools.combinations(mnemonics[group_idx_1], groups[group_idx_1][0]):
                        for members_2 in itertools.combinations(mnemonics[group_idx_2], groups[group_idx_2][0]):
                            seed_gen = Slip39SeedGenerator(list(members_2) + list(members_1))
                            self.assertEqual(master_secret, seed_gen.Generate(passphrase))

                # Wrong passphrase results in a different seed
                seed_gen = Slip39SeedGenerator(mnemonics[0] + mnemonics[1][:2])
                self.assertNotEqual(master_secret, seed_gen.Generate(passphrase + "x"))
                self.assertNotEqual(master_secret, seed_gen.Generate())

    # Test generation with default parameters (single share)
    def test_generate_default(self):
        for words_num in Slip39WordsNum:
            mnemonics = Slip39MnemonicGenerator().FromWordsNumber(words_num)
            self.assertEqual(1, len(mnemonics))
            self.assertEqual(1, len(mnemonics[0]))
            self.assertEqual(words_num, mnemonics[0][0].WordsCount())

            share = Slip39MnemonicDecoder().Decode(mnemonics[0][0])
            self.assertTrue(share.extendable)
            self.assertEqual(1, share.iteration_exponent)
            self.assertEqual(1, share.group_threshold)
            self.assertEqual(1, share.group_count)
            self.assertEqual(1, share.member_threshold)

            # A single mnemonic can be passed directly, also as string
            self.assertEqual(Slip39SeedGenerator(mnemonics[0][0]).Generate(),
                             Slip39SeedGenerator(mnemonics[0][0].ToStr()).Generate())

        # Integer words number
        self.assertEqual(20, Slip39MnemonicGenerator().FromWordsNumber(20)[0][0].WordsCount())

    # Test words list
    def test_words_list(self):
        words_list = Slip39WordsListGetter.Instance().GetByLanguage(Slip39Languages.ENGLISH)
        self.assertEqual(1024, words_list.Length())
        self.assertEqual("academic", words_list.GetWordAtIdx(0))
        self.assertEqual("zero", words_list.GetWordAtIdx(1023))
        self.assertRaises(TypeError, Slip39WordsListGetter.Instance().GetByLanguage, 0)

    # Test duplicated shares
    def test_duplicated_shares(self):
        mnemonics = TEST_VECT[3]["mnemonics"]
        seed = Slip39SeedGenerator(mnemonics + [mnemonics[0]]).Generate(TEST_VECT_PASSPHRASE)
        self.assertEqual(TEST_VECT[3]["master_secret"], binascii.hexlify(seed))

    # Test invalid generator parameters
    def test_invalid_generator_params(self):
        for params in TEST_GENERATOR_INVALID_PARAMS:
            self.assertRaises(ValueError, Slip39MnemonicGenerator, **params)

    # Test invalid generation
    def test_invalid_generate(self):
        generator = Slip39MnemonicGenerator(iteration_exponent=0)

        for words_num in (12, 19, 21, 24, 59):
            self.assertRaises(ValueError, generator.FromWordsNumber, words_num)
        for master_secret in (b"\x00" * 14, b"\x00" * 15, b"\x00" * 17):
            self.assertRaises(ValueError, generator.FromMasterSecret, master_secret)
        for passphrase in ("café", "new\nline", "tab\t"):
            self.assertRaises(ValueError, generator.FromMasterSecret, bytes(16), passphrase)

    # Test backup extension
    def test_extend(self):
        decoder = Slip39MnemonicDecoder()

        # Extendable vectors: 1-of-1 (128 and 256 bits) and 2-of-3 (128 and 256 bits)
        for test in (TEST_VECT[41], TEST_VECT[42], TEST_VECT[43], TEST_VECT[44]):
            old_share = decoder.Decode(test["mnemonics"][0])
            new_groups = Slip39MnemonicGenerator(group_threshold=2,
                                                 groups=[(1, 1), (2, 3), (3, 5)],
                                                 extendable=False,
                                                 iteration_exponent=5).FromMnemonics(test["mnemonics"])

            # New identifier, same extendable flag and iteration exponent, new scheme
            for group_idx, group in enumerate(new_groups):
                for mnemonic in group:
                    share = decoder.Decode(mnemonic)
                    self.assertNotEqual(old_share.identifier, share.identifier)
                    self.assertTrue(share.extendable)
                    self.assertEqual(old_share.iteration_exponent, share.iteration_exponent)
                    self.assertEqual(group_idx, share.group_index)
                    self.assertEqual(2, share.group_threshold)
                    self.assertEqual(3, share.group_count)
                    self.assertEqual(len(old_share.value), len(share.value))

            # Same seed for any passphrase
            new_seed_gen = Slip39SeedGenerator(new_groups[0] + new_groups[2][2:])
            self.assertEqual(test["master_secret"], binascii.hexlify(new_seed_gen.Generate(TEST_VECT_PASSPHRASE)))
            for passphrase in ("", "other passphrase"):
                self.assertEqual(Slip39SeedGenerator(test["mnemonics"]).Generate(passphrase),
                                 new_seed_gen.Generate(passphrase))

            # Shares of the two sets cannot be mixed
            self.assertRaises(ValueError, Slip39SeedGenerator, new_groups[0] + test["mnemonics"][:1])

            # The new set can be extended again
            newer_groups = Slip39MnemonicGenerator(groups=[(2, 2)]).FromMnemonics(new_groups[1][:2] + new_groups[2][:3])
            self.assertEqual(test["master_secret"],
                             binascii.hexlify(Slip39SeedGenerator(newer_groups[0]).Generate(TEST_VECT_PASSPHRASE)))

        # Extension of generated shares, from a single share to a 2-of-3 scheme
        mnemonic = Slip39MnemonicGenerator(iteration_exponent=2).FromWordsNumber(Slip39WordsNum.WORDS_NUM_33,
                                                                                 "pass")[0][0]
        new_groups = Slip39MnemonicGenerator(groups=[(2, 3)]).FromMnemonics(mnemonic)
        self.assertEqual(2, decoder.Decode(new_groups[0][0]).iteration_exponent)
        self.assertEqual(Slip39SeedGenerator(mnemonic).Generate("pass"),
                         Slip39SeedGenerator(new_groups[0][1:]).Generate("pass"))

    # Test invalid backup extension
    def test_invalid_extend(self):
        generator = Slip39MnemonicGenerator(groups=[(2, 3)])

        # Not extendable (1-of-1 and 2-of-3)
        self.assertRaises(ValueError, generator.FromMnemonics, TEST_VECT[0]["mnemonics"])
        self.assertRaises(ValueError, generator.FromMnemonics, TEST_VECT[3]["mnemonics"])
        # Shares cannot be combined
        self.assertRaises(ValueError, generator.FromMnemonics, [])
        self.assertRaises(ValueError, generator.FromMnemonics, TEST_VECT[42]["mnemonics"][:1])
        self.assertRaises(MnemonicChecksumError, generator.FromMnemonics, TEST_VECT[1]["mnemonics"])

    # Test invalid seed generation
    def test_invalid_seed_generator(self):
        self.assertRaises(ValueError, Slip39SeedGenerator, [])

        seed_gen = Slip39SeedGenerator(TEST_VECT[0]["mnemonics"])
        self.assertRaises(ValueError, seed_gen.Generate, "café")

        # Shares with different lengths (same identifier and parameters)
        share = Slip39MnemonicDecoder().Decode(TEST_VECT[3]["mnemonics"][0])
        other_share = dataclasses.replace(share, member_index=share.member_index ^ 1, value=bytes(32))
        self.assertRaises(ValueError,
                          Slip39SeedGenerator,
                          [TEST_VECT[3]["mnemonics"][0], Slip39MnemonicEncoder().Encode(other_share)])


class Slip39ShamirTests(unittest.TestCase):
    # Test GF(256) arithmetic
    def test_gf256(self):
        # Examples from FIPS-197
        self.assertEqual(0xC1, Slip39Gf256.Mul(0x57, 0x83))
        self.assertEqual(0x01, Slip39Gf256.Mul(0x53, 0xCA))
        self.assertEqual(0xCA, Slip39Gf256.Inv(0x53))
        for a in range(1, 256):
            self.assertEqual(1, Slip39Gf256.Mul(a, Slip39Gf256.Inv(a)))
            self.assertEqual(0, Slip39Gf256.Mul(a, 0))

    # Test secret splitting and recovery
    def test_split_recover(self):
        secret = bytes(range(16))
        for threshold, shares_num in ((1, 1), (1, 3), (2, 2), (3, 5), (16, 16)):
            shares = Slip39Shamir.SplitSecret(threshold, shares_num, secret)
            self.assertEqual(list(range(shares_num)), [share_x for share_x, _ in shares])

            for subset in itertools.islice(itertools.combinations(shares, threshold), 20):
                self.assertEqual(secret, Slip39Shamir.RecoverSecret(threshold, subset))
            # Interpolating at a share index results in the share value
            self.assertEqual(shares[-1][1], Slip39Shamir.Interpolate(shares[-threshold:], shares[-1][0]))

        # Tampered share
        shares = Slip39Shamir.SplitSecret(2, 3, secret)
        tampered_share = (shares[1][0], bytes([shares[1][1][0] ^ 1]) + shares[1][1][1:])
        self.assertRaises(ValueError, Slip39Shamir.RecoverSecret, 2, [shares[0], tampered_share])

    # Test invalid parameters
    def test_invalid_params(self):
        secret = bytes(16)
        for threshold, shares_num in ((0, 1), (2, 1), (17, 17)):
            self.assertRaises(ValueError, Slip39Shamir.SplitSecret, threshold, shares_num, secret)

        self.assertRaises(ValueError, Slip39Shamir.Interpolate, [], 0)
        self.assertRaises(ValueError, Slip39Shamir.Interpolate, [(0, secret), (0, secret)], 1)
        self.assertRaises(ValueError, Slip39Shamir.Interpolate, [(0, secret), (1, secret + b"\x00")], 2)
