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
    Sr25519PrivateKey, Sr25519PublicKey, Substrate, SubstrateCoins, SubstrateKeyError, SubstratePath, SubstratePathElem,
    SubstratePrivateKey, SubstratePublicKey
)
from bip_utils.substrate.conf import SubstrateCoinConf
from bip_utils.substrate.substrate import SubstrateConst
from tests.ecc.test_ecc import (
    TEST_SR25519_PRIV_KEY, TEST_SR25519_PUB_KEY, TEST_VECT_SR25519_PRIV_KEY_INVALID, TEST_VECT_SR25519_PUB_KEY_INVALID
)


# Test vector
# Only Kusama and Polkadot are tested, since the keys are always the same for all coins (only the address format changes)
# The other coins are tested in TEST_VECT_ADDR
TEST_VECT = [
    # Kusama
    {
        "coin": SubstrateCoins.KUSAMA,
        "names": ("Kusama", "KSM"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "master": {
            "path": "",
            "pub_key": "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972",
            "priv_key": "2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8",
            "address": "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1",
        },
        "der_paths": [
            # //0
            {
                "path_elem": "//0",
                "path": "//0",
                "pub_key": "5244eb2b8a9f975c603485c5a76eeec41fdad88aa6ef204b7c56691940ad1671",
                "priv_key": "8491e5398431cfa719c13edfd90053ca69eaad2b03e2a79cf0b7edefff16bf0f7ce29f7eb4d9309652f2118481a2c1d9909a6f267baf7152ea4f2d2de4a1bdc4",
                "address": "ESBvAXXVa7fDASV2wTiWJU2L2op4671sHQeKqiXCWDz6uGu",
            },
            # //0/1
            {
                "path_elem": "/1",
                "path": "//0/1",
                "pub_key": "f019beb77158432792c6318e214d93e5913f7daeb6ee26f37999bbb5c0eab15b",
                "priv_key": "f777bb567168739dde16b475e50af56bd67da49b4ab9d6b287626c0556c33107",
                "address": "J18f7g66JVFpm7jS52dLtTtu6vfuwLtQUwuUKVCUzMtYAhW",
            },
            # //0/1//hard
            {
                "path_elem": "//hard",
                "path": "//0/1//hard",
                "pub_key": "5c68cdc5189e61a50381c1acc2e58b1e3c2c3f6160ff5619b3642e21a2d05901",
                "priv_key": "f3df105fe5c90558e518c33554c307ae7c9aa2e98f76af085af94d0ca951450dde2ac074c36b0db553005479eb69eca42d7881c9a61c44b0eabd7cdf35dff9e5",
                "address": "EfV4E1FJvqF4CsD2qnTPU2ibyTCLNeDZcHobieNBy33ywfZ",
            },
            # //0/1//hard/soft
            {
                "path_elem": "/soft",
                "path": "//0/1//hard/soft",
                "pub_key": "a26993d6b4d61dffafbba5ca1ddf2a2ed3aadf452f0561d40f43fd2f2ce67642",
                "priv_key": "ed4756e3eda8ce99ce50bfdb2cdbccf8f1d46be76a63a775bf412ea30fc86f0e",
                "address": "GFGdy5BPZPPcSoew8B9rKGKW4wQQcyGoEwS7rkoYiVD2m2C",
            },
        ],
    },
    # Polkadot
    {
        "coin": SubstrateCoins.POLKADOT,
        "names": ("Polkadot", "DOT"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "master": {
            "path": "",
            "pub_key": "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972",
            "priv_key": "2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8",
            "address": "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo",
        },
        "der_paths": [
            # //0
            {
                "path_elem": "//0",
                "path": "//0",
                "pub_key": "5244eb2b8a9f975c603485c5a76eeec41fdad88aa6ef204b7c56691940ad1671",
                "priv_key": "8491e5398431cfa719c13edfd90053ca69eaad2b03e2a79cf0b7edefff16bf0f7ce29f7eb4d9309652f2118481a2c1d9909a6f267baf7152ea4f2d2de4a1bdc4",
                "address": "12rsQBSiizNCu3dZDshfkVwB34XDwiqyVQJP6URvGo31YGdp",
            },
            # //0/1
            {
                "path_elem": "/1",
                "path": "//0/1",
                "pub_key": "f019beb77158432792c6318e214d93e5913f7daeb6ee26f37999bbb5c0eab15b",
                "priv_key": "f777bb567168739dde16b475e50af56bd67da49b4ab9d6b287626c0556c33107",
                "address": "16Rp98bHKijoWeJod1Gab5w3c8e5oa5r2bqeExCbZHAuydVR",
            },
            # //0/1//hard
            {
                "path_elem": "//hard",
                "path": "//0/1//hard",
                "pub_key": "5c68cdc5189e61a50381c1acc2e58b1e3c2c3f6160ff5619b3642e21a2d05901",
                "priv_key": "f3df105fe5c90558e518c33554c307ae7c9aa2e98f76af085af94d0ca951450dde2ac074c36b0db553005479eb69eca42d7881c9a61c44b0eabd7cdf35dff9e5",
                "address": "136AYEvSYM5nk64HDn2QdfVsK1AcE1PBBjBYNMMmGFr5RUXS",
            },
            # //0/1//hard/soft
            {
                "path_elem": "/soft",
                "path": "//0/1//hard/soft",
                "pub_key": "a26993d6b4d61dffafbba5ca1ddf2a2ed3aadf452f0561d40f43fd2f2ce67642",
                "priv_key": "ed4756e3eda8ce99ce50bfdb2cdbccf8f1d46be76a63a775bf412ea30fc86f0e",
                "address": "14fx7yzNcydwJKzj84R76WjUD6epJFiERMqAtVUCd1JEULPK",
            },
        ],
    },
]

# Test vector for addresses
TEST_VECT_ADDR = [
    # Acala
    {
        "coin": SubstrateCoins.ACALA,
        "names": ("Acala", "ACA"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "23C6Cz54QyBMNvrhjnFVS1dn6EwtZxDc3KyR71xJnXTNSDst",
            },
            {
                "path_elem": "//0",
                "address": "22jTz6rkZu7UTdgCHCVuXWbRVuxAVZ9BNoqhFJrvuLytMG3W",
            },
            {
                "path_elem": "/1",
                "address": "26JQj41KAdV55EMSgL4pN6bJ4z52MQP3v1NxPndcBq7nnh49",
            },
            {
                "path_elem": "//hard",
                "address": "22xm8ALUPFq4Jg6vH6peQgA7mrbYmqgP58irXBnmtonxEhJQ",
            },
            {
                "path_elem": "/soft",
                "address": "24YYhuQQTtPCrv3NBPDLsXPifx5kr61SJmNV3KuDFZF7HQ9y",
            },
        ],
    },
    # Bifrost
    {
        "coin": SubstrateCoins.BIFROST,
        "names": ("Bifrost", "BNC"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "e3TB1uSsogSkhEr7ejPvQa5WJNiMDhXHZkteHP6w75RK3kr",
            },
            {
                "path_elem": "//0",
                "address": "dapx8h92jcZqQ4Lf4yp1uXiuyNzGpd6d3dAnaHj3vbwE45t",
            },
            {
                "path_elem": "/1",
                "address": "h9mh5qhdTzASzjb4CYirVXbV3Vr8fryAFARw44QLQjqfUh7",
            },
            {
                "path_elem": "//hard",
                "address": "dp86CArr6L9gSV4eyJYu56RBv2NZ7AJKNWL4TDa3PR17ED2",
            },
            {
                "path_elem": "/soft",
                "address": "fPufwEnvitJEgRWZFhFMvL261WadMVMZ19xabL1Q8sAABLs",
            },
        ],
    },
    # ChainX
    {
        "coin": SubstrateCoins.CHAINX,
        "names": ("ChainX", "PCX"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "5RxWziUmUrv4gvcUXtAJGegE4jotSBdJTJot2FpYXbfx1GKH",
            },
            {
                "path_elem": "//0",
                "address": "5RVtmqGTdnrBmdRy5JQiN9dsUQpAMnYsnngAAYjAeRCTvPST",
            },
            {
                "path_elem": "/1",
                "address": "5V4qWnR2EXDnPE7DURydCjdk3Uw2DdnkKzDRK2VqvuLNMvf8",
            },
            {
                "path_elem": "//hard",
                "address": "5RjButkBT9Zmcfrh5CjTFKCZkMTYe565V7ZKSRf1dt1XoRd3",
            },
            {
                "path_elem": "/soft",
                "address": "5TJyVdp7Xn7vAuo8yV89iASAeSwkiKR8ikCwxZmSzdTgrFaU",
            },
        ],
    },
    # Edgeware
    {
        "coin": SubstrateCoins.EDGEWARE,
        "names": ("Edgeware", "EDG"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "jq7S1SrG6ZAukeK2BcRJJqW9nX1QQL3UWK2Fy2QPxfubJ2z",
            },
            {
                "path_elem": "//0",
                "address": "jNVD8EYR2VHzTToZbrqPoo9ZTXHL1FcozBJQFw2WnCRWKhZ",
            },
            {
                "path_elem": "/1",
                "address": "nwRx5P71krtc493xjRkEPo28Xe9BrVVMBiZYjhhoGLKwrvx",
            },
            {
                "path_elem": "//hard",
                "address": "jbnMBiGEPCsqVtXZWBaGyMqqQAfcHnpWK4Tg8rsWF1VPZBC",
            },
            {
                "path_elem": "/soft",
                "address": "mBZvvnCK1m2PjpyTnaGjpbSjVesgY7sjwi6CGyJrzTeSUD4",
            },
        ],
    },
    # Generic Substrate
    {
        "coin": SubstrateCoins.GENERIC,
        "names": ("Generic Substrate", ""),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH",
            },
            {
                "path_elem": "//0",
                "address": "5DvaFrBesD6jTWd3GEefcM72BSXaFRHqQuZtwBSZii1VMnuP",
            },
            {
                "path_elem": "/1",
                "address": "5HVWzoLDTwUL57JHfNDaSw6tkWeS7GXhx77A5fDF1C9Po2Hb",
            },
            {
                "path_elem": "//hard",
                "address": "5E9sPufNgZpKJZ3mG8yQVWfiTPAxXhq37ET4D4NQiApZF5Ta",
            },
            {
                "path_elem": "/soft",
                "address": "5FjeyejJmCNTrnzDARN6xMuKMUfAbxA6Ls6gjCUr4vGiHryc",
            },
        ],
    },
    # Karura
    {
        "coin": SubstrateCoins.KARURA,
        "names": ("Karura", "KAR"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "qcmgzzFePRu4p3mviVSgD6voGfJTaxZfSs9sefhrpGPsejg",
            },
            {
                "path_elem": "//0",
                "address": "qA9U7mwoKN29WsGU8jrmi4aCwfaPBt8zvjS1waKydnunpgj",
            },
            {
                "path_elem": "/1",
                "address": "tj6D4vWQ3jcm7YWsGJmcJ4Sn1nSF381Y8GhARM1G7vpECPT",
            },
            {
                "path_elem": "//hard",
                "address": "qPScBFfcg5bzZHzU34besdGUtJxfURLhFcbHpWAy6byfrDt",
            },
            {
                "path_elem": "/soft",
                "address": "ryEBvKbhJdkYoESNKTJ7irsNyoAjikPvtGDoxccKr48ioGs",
            },
        ],
    },
    # Moonbeam
    {
        "coin": SubstrateCoins.MOONBEAM,
        "names": ("Moonbeam", "GLMR"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "Vdsr26TpvgnABWPYYaQPbuRfbEwmQZeg1uyZYW5Ht6mrn52i6",
            },
            {
                "path_elem": "//0",
                "address": "VdsPPsaccqi6Jb6N37pe1zvdEecmgVFbbFTRpeNCWDbPHzB9S",
            },
            {
                "path_elem": "/1",
                "address": "VdvxLcXmBSSTuCh3HWxCvqWd7DgtYM6qTney5nqyBW5XCRRE5",
            },
            {
                "path_elem": "//hard",
                "address": "Vdsch1e6Lf4otS8nm7ixkt6BvvZR4mY8nwnJyvF8MD4CMsAjG",
            },
            {
                "path_elem": "/soft",
                "address": "VduCUbPAGjhN2zNjD21MTLwRXpeuGqnTrBQxcSPEnZoeWvEMF",
            },
        ],
    },
    # Moonriver
    {
        "coin": SubstrateCoins.MOONRIVER,
        "names": ("Moonriver", "MOVR"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "VkGEEdxUjHQ8hW9SEYUh856gnbzvE5NyKzB1wspT9jVuz5nr2",
            },
            {
                "path_elem": "//0",
                "address": "VkFmcR5GRSL4parFj5twYAbeS1fvVzytuKetE27MmrKSVzmcJ",
            },
            {
                "path_elem": "/1",
                "address": "VkKLZA2Qz34SRCSvyV2WT1BeJak3Mrq8mrrRVAb8T8oaQSAGB",
            },
            {
                "path_elem": "//hard",
                "address": "VkFzuZ8k9FgnQRtgT5oGH3mD8HcZtHGS71ymPHzHcqnFZsphc",
            },
            {
                "path_elem": "/soft",
                "address": "VkHah8sp5LKLYz8ctz5eyWcSjBi46MWmAFcR1p8Q4CXhivpxg",
            },
        ],
    },
    # Phala Network
    {
        "coin": SubstrateCoins.PHALA,
        "names": ("Phala Network", "PHA"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "42wHNpu86nftW6wyrRqxz2xH1womfcp1p943QgpL3dM84sw5",
            },
            {
                "path_elem": "//0",
                "address": "42Uf9wgpFic1aomUPr6P5XuvRcp3bDjb9cvKYyixASsdyhb9",
            },
            {
                "path_elem": "/1",
                "address": "463bttqNrSycCQSinyfHv7unzgvuT4yTgpTahTVdSw1YR9yF",
            },
            {
                "path_elem": "//hard",
                "address": "42hxJ1AY55KbRrCCPkR7xhUchZTRsWGnqwoUpreo9ughrtzg",
            },
            {
                "path_elem": "/soft",
                "address": "44HjskEU9hsjz68eJ2opRYiDbewdwkbr5aT7LzmEWf8ruyVP",
            },
        ],
    },
    # Plasm Network
    {
        "coin": SubstrateCoins.PLASM,
        "names": ("Plasm Network", "PLM"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "YFnv2N3VWoibdqPD7rNYWJerpERJ3516dCm2bjoUFUw2k8a",
            },
            {
                "path_elem": "//0",
                "address": "XoAh99jeSjqgLeskY6ne1GJGVEhDdzaS753AteRb51SwtjA",
            },
            {
                "path_elem": "/1",
                "address": "bN7S6JJFB7SHwL89ffhUbGAqZMZ5VESyJcJKNR6sZ9MPMv6",
            },
            {
                "path_elem": "//hard",
                "address": "Y2TqCdTToTRXP5bkSRXXApzYRt5VvXn8RxCSmaGaXpWpxwF",
            },
            {
                "path_elem": "/soft",
                "address": "ZcFQwhPYS1a5d23eipDz24bSXNHaArqN4bpxughwHGfsm5z",
            },
        ],
    },
    # Sora
    {
        "coin": SubstrateCoins.SORA,
        "names": ("Sora", "XOR"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "cnTon6cV8Ze8ATHT1tZdHregCc3wBc8vfg7P5o2TtwdUoRf4m",
            },
            {
                "path_elem": "//0",
                "address": "cnTM9sjGpia4HXzGWRyshx9dr1iwTXjrF1bFMwKNX4T1KLV73",
            },
            {
                "path_elem": "/1",
                "address": "cnWv6cgRPKJRt9awkq7Scnjdiao4KPb67Ynnd5o9CLw9DmtQQ",
            },
            {
                "path_elem": "//hard",
                "address": "cnTaT1nkYXvmsP2hERtCSqKCYHfaqp2PShv8XDCJN3upPDkzL",
            },
            {
                "path_elem": "/soft",
                "address": "cnVAEbXpUcZL1wGdgLAb9JAS9Bm53tGiVwYn9jLQoQfGYGkj2",
            },
        ],
    },
    # Stafi
    {
        "coin": SubstrateCoins.STAFI,
        "names": ("Stafi", "FIS"),
        "seed": b"4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e",
        "der_paths": [
            {
                "path_elem": "",
                "address": "334gnuV6FsvcwWuLo73jD2J2Z6Nq7nWovjWjFrPKR5QFFn9S",
            },
            {
                "path_elem": "//0",
                "address": "32c4a2GnQork2DiqLXJ9JXFfxmP73PSPGDP1Q9HwXtvmAfQR",
            },
            {
                "path_elem": "/1",
                "address": "36B1JyRM1YELdpQ5jes497FYXqVxuEgFoQvGYd4cpP4fc2qM",
            },
            {
                "path_elem": "//hard",
                "address": "32qMi5kWEAaKsG9ZLRctBgpNEi2VKfyaxYGAg2DnXMjq3jrR",
            },
            {
                "path_elem": "/soft",
                "address": "34R9HppSJo8URW61Ei1aeY3y8oWhPvJeCAuoCALDt7Bz6h83",
            },
        ],
    },
]

# Tests for public derivation
TEST_VECT_PUBLIC_DER = {
    "coin": SubstrateCoins.POLKADOT,
    "master": {
        "path": "",
        "pub_key": "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972",
        "priv_key": "2ec306fc1c5bc2f0e3a2c7a6ec6014ca4a0823a7d7d42ad5e9d7f376a1c36c0d14a2ddb1ef1df4adba49f3a4d8c0f6205117907265f09a53ccf07a4e8616dfd8",
        "address": "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo",
    },
    "der_paths": [
        # /0
        {
            "path_elem": "/0",
            "path": "/0",
            "pub_key": "0c4f096369eaeea12066045a810c9e5ea73b81d420c1b606324050ec477ab676",
            "address": "1H946gSKhhSKfnXR8ekj9EDH4DCzfSB8zAVfG3GtfauiuaQ",
        },
        # /0/1
        {
            "path_elem": "/1",
            "path": "/0/1",
            "pub_key": "1e0d3b9137a3b9a5a443170730dcaad8d96c807cef2a1f15b6955ac89bd66e7e",
            "address": "1gQNKAidMzgVFTp6CttbEehwagJ9JZAV3Sb1ZDHgd48RDr8",
        },
        # /0/1//hard : shall trigger an exception
        {
            "path_elem": "//hard",
        },
    ],
}

# Invalid seed
TEST_SEED_ERR = b"\x00" * (SubstrateConst.SEED_MIN_BYTE_LEN - 1)
# Generic seed for testing
TEST_SEED = b"\x00" * SubstrateConst.SEED_MIN_BYTE_LEN


#
# Tests
#
class SubstrateTests(unittest.TestCase):
    # Run all tests in test vector using FromSeed for construction
    def test_from_seed(self):
        for test in TEST_VECT:
            # Create from seed
            substrate_ctx = Substrate.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test coin configuration
            self.assertTrue(isinstance(substrate_ctx.CoinConf(), SubstrateCoinConf))

            # Test coin names
            coin_names = substrate_ctx.CoinConf().CoinNames()
            self.assertEqual(test["names"], (coin_names.Name(), coin_names.Abbreviation()))

            # Test object
            self.__test_substrate_obj(substrate_ctx, test["master"], False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                substrate_ctx = substrate_ctx.ChildKey(der_path["path_elem"])
                self.__test_substrate_obj(substrate_ctx, der_path, False)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        for test in TEST_VECT:
            # Create from seed
            substrate_ctx = Substrate.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test derivation paths
            for der_path in test["der_paths"]:
                substrate_ctx = substrate_ctx.DerivePath(der_path["path_elem"])
                self.__test_substrate_obj(substrate_ctx, der_path, False)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        for test in TEST_VECT:
            # Create from seed
            substrate_ctx = Substrate.FromSeedAndPath(binascii.unhexlify(test["seed"]), "", test["coin"])
            # Test object
            self.__test_substrate_obj(substrate_ctx, test["master"], False)

            # Test derivation paths
            for der_path in test["der_paths"]:
                substrate_ctx = Substrate.FromSeedAndPath(binascii.unhexlify(test["seed"]), der_path["path"], test["coin"])
                self.__test_substrate_obj(substrate_ctx, der_path, False)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_private_key(self):
        for test in TEST_VECT:
            priv_key_bytes = binascii.unhexlify(test["master"]["priv_key"])

            # Test both from bytes and key object
            self.__test_from_private_key(test, priv_key_bytes)
            self.__test_from_private_key(test, Sr25519PrivateKey(priv_key_bytes))

    # Test public derivation
    def test_public_derivation(self):
        test_vect = TEST_VECT_PUBLIC_DER

        # Create from public key
        pub_key_bytes = binascii.unhexlify(test_vect["master"]["pub_key"])
        # Bytes
        substrate_ctx = Substrate.FromPublicKey(pub_key_bytes, test_vect["coin"])
        self.__test_public_derivation(test_vect, substrate_ctx)
        # Key object
        substrate_ctx = Substrate.FromPublicKey(Sr25519PublicKey(pub_key_bytes), test_vect["coin"])
        self.__test_public_derivation(test_vect, substrate_ctx)

        # Create from private key and convert to public
        substrate_ctx = Substrate.FromPrivateKey(binascii.unhexlify(test_vect["master"]["priv_key"]), test_vect["coin"])
        substrate_ctx.ConvertToPublic()
        self.__test_public_derivation(test_vect, substrate_ctx)

    # Test addresses of other coins
    def test_coins_addr(self):
        for test in TEST_VECT_ADDR:
            # Create from seed
            substrate_ctx = Substrate.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test coin names
            coin_names = substrate_ctx.CoinConf().CoinNames()
            self.assertEqual(test["names"], (coin_names.Name(), coin_names.Abbreviation()))

            # Test derivation paths
            for der_path in test["der_paths"]:
                substrate_ctx = substrate_ctx.DerivePath(der_path["path_elem"])
                self.assertEqual(der_path["address"], substrate_ctx.PublicKey().ToAddress())

    # Test invalid seed
    def test_invalid_seed(self):
        self.assertRaises(ValueError, Substrate.FromSeed, TEST_SEED_ERR, SubstrateCoins.POLKADOT)

    # Test invalid parameters
    def test_invalid_params(self):
        self.assertRaises(TypeError, Substrate.FromSeed, TEST_SEED, 0)
        self.assertRaises(TypeError, Substrate.FromSeedAndPath, TEST_SEED, 0)
        self.assertRaises(TypeError, Substrate.FromPrivateKey, TEST_SR25519_PRIV_KEY, 0)
        self.assertRaises(TypeError, Substrate.FromPublicKey, TEST_SR25519_PUB_KEY, 0)

        for test in TEST_VECT_SR25519_PUB_KEY_INVALID:
            self.assertRaises(SubstrateKeyError, Substrate.FromPublicKey, binascii.unhexlify(test), SubstrateCoins.POLKADOT)
        for test in TEST_VECT_SR25519_PRIV_KEY_INVALID:
            self.assertRaises(SubstrateKeyError, Substrate.FromPrivateKey, binascii.unhexlify(test), SubstrateCoins.POLKADOT)

    # Test from private key
    def __test_from_private_key(self, test, priv_key):
        # Create from key
        substrate_ctx = Substrate.FromPrivateKey(priv_key, test["coin"])
        # Test object
        self.__test_substrate_obj(substrate_ctx, test["master"], False)

        # Test derivation paths
        for der_path in test["der_paths"]:
            substrate_ctx = substrate_ctx.DerivePath(der_path["path_elem"])
            self.__test_substrate_obj(substrate_ctx, der_path, False)

    # Test public derivation
    def __test_public_derivation(self, test, substrate_ctx):
        # Test object
        self.__test_substrate_obj(substrate_ctx, test["master"], True)

        # Test derivation paths
        for der_path in test["der_paths"]:
            if SubstratePathElem(der_path["path_elem"]).IsSoft():
                substrate_ctx = substrate_ctx.ChildKey(der_path["path_elem"])
                self.__test_substrate_obj(substrate_ctx, der_path, True)
            else:
                self.assertRaises(SubstrateKeyError, substrate_ctx.ChildKey, der_path["path_elem"])

    # Test Substrate object
    def __test_substrate_obj(self, substrate_obj, test, is_watch_only):
        if is_watch_only:
            self.assertRaises(SubstrateKeyError, substrate_obj.PrivateKey)
        else:
            self.assertTrue(isinstance(substrate_obj.PrivateKey(), SubstratePrivateKey))

            if "path_elem" in test:
                if SubstratePathElem(test["path_elem"]).IsHard():
                    self.assertEqual(test["priv_key"], substrate_obj.PrivateKey().Raw().ToHex())
                else:
                    # Consider only the first 32 bytes for public derivation
                    self.assertEqual(test["priv_key"][:64], substrate_obj.PrivateKey().Raw().ToHex()[:64])
            else:
                self.assertEqual(test["priv_key"], substrate_obj.PrivateKey().Raw().ToHex())

        self.assertTrue(isinstance(substrate_obj.PublicKey(), SubstratePublicKey))
        self.assertTrue(isinstance(substrate_obj.Path(), SubstratePath))

        self.assertEqual(is_watch_only, substrate_obj.IsPublicOnly())
        self.assertEqual(test["path"], substrate_obj.Path().ToStr())
        self.assertEqual(test["pub_key"], substrate_obj.PublicKey().RawCompressed().ToHex())
        self.assertEqual(test["pub_key"], substrate_obj.PublicKey().RawUncompressed().ToHex())
        self.assertEqual(test["address"], substrate_obj.PublicKey().ToAddress())
