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
from bip_utils import Bip32Ed25519Kholaw, Bip32KeyIndex, Bip32KholawEd25519, EllipticCurveTypes
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import Bip32Slip10MstKeyGeneratorConst
from tests.bip.bip32.test_bip32_base import Bip32BaseTests


# Test vector
TEST_VECT = [
    {
        "seed": b"000102030405060708090a0b0c0d0e0f",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFHnJTiLZTyWpM17B9Re2FwsPtDY8xguW4hC6MjhpWPhjL4DrcY5PegXBdGydvmXeTmBQem4kqAsGmmzAztdBWPsnzee6e4b",
            "ex_priv": "xprv3QESAWYc9vDdZVJ6UYQ2WTCngDACKBxRxmHRKxFvPU5jR4TENj7o6ZJkMq25mSf9LUPDQneTp21KtNNhE48VPqkBPJsnrRyFrQ1hzx6mPV4ggmcU1MnTTfmSE4HnvYhQC7sF4ub3DrWYnWWqhRMsPb5",
            "pub_key": "00adfd5a2197b97cf659ad4cbffc60c5e37ffca638b20c5d94d6ae4f47ff065487",
            "priv_key": "587049cb3630fb0f04b98d9e8b24a10a75e2b028d556c13877cecb6ab12e725f831a58390f707d4f623b7e2916239bfd821758e53d3e81aeac9e967714064c55",
            "chain_code": "4b11419b53d0c31c6a2048b1e92c3152f7bc1dce6469cf88787e92bc7ddd4a23",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0'
            {
                "path": "m/0'",
                "index": Bip32KeyIndex.HardenIndex(0),
                "ex_pub": "xpub69He9C7F8RHsxzNPPmgCJd6h4vamJG45XtFxyDnACEefK6jVJ1zfoQCQ3doRU1bzxVHgQ5CSPDYZGTrsv2cxe89udKGjwsKGKULfV4aKKiU",
                "ex_priv": "xprv3RCxbHQi5kwGRXbhownFoHbqBFWC7bCDmuMcAD5mthRdnuy2bWy4By3UkyuDpcVu1MAreNrtpnHSejnP43dmBC5PCpLJTTGQqJJ91gShe4MssyMnomkapFNtfHbu6s9yMLBgbKck6cbpUVV7MVjNAYZ",
                "pub_key": "0078701ff87a9da875b1aca15421a7974ab753df5f1dd8abff20aa1cca0eca32ab",
                "priv_key": "f8c5fe7ef12d7a7f787aa7c3ba107b07f15b9de49528b681f3229f5cb62e725fb74792aee99adb5aeb18e6496d3c8b4d4f84186aacd65d5bd4067c7b39a80fce",
                "chain_code": "bbd2e77e76697e7a062742e8d1018b4981680e1b06a46d110c91719cde1babff",
                "parent_fprint": "be56a6f4",
            },
            # m/0'/1
            {
                "path": "m/0'/1",
                "index": 1,
                "ex_pub": "xpub6A7CytpGCBTkiDhakfW9vvUppUX4VrTdD1xCXp7H4hr5Rj9iFQCxtBaXN1fGUEhCZhJQxw5CkoBW9KGDg4jQUMfZynpjkE1t2gxkNKzo1Gf",
                "ex_priv": "xprv3RT68z5UEKE7wNtodgS9Qb95WkzidZ9cZ363U6kymS5uS5xHKi4ZYcJLqmhxMeG8nDm2H8n8a8nygoAejhSbRAdF7DEqT4VMNsQ96h2n7gC8B4cHcNWSD1pC9hAjSr6rqJvTervsymJtTQU8KugTm1Y",
                "pub_key": "002a0fcae305362bc3516ae4eabbeb51e1dfaa7fdf234dbe5f05274adf69b1a3e1",
                "priv_key": "b08950f1e6198ae164f7a2bb458890565887b09fb3fc25bb1cfd1340bb2e725f2a5f64e1bbc9c3d13a35649178cd23d04b700e3aae9fb2f2c119b1b7e01790d8",
                "chain_code": "1911b561b3cc8e1b48ed9e447e3376bbc1ce3623be19580dbffa54ae7070a601",
                "parent_fprint": "2dea377a",
            },
            # m/0'/1/2'
            {
                "path": "m/0'/1/2'",
                "index": Bip32KeyIndex.HardenIndex(2),
                "ex_pub": "xpub6DQVogkHGVzAf44J3TRZRNXeucxYdhGpfND8hGYif7EgrUrPgcEpgEg9ipS1N6fGA3zFjp5pXSnpZKXPKTDphW1mWgMwq3W1KMmZxfed2ZS",
                "ex_priv": "xprv3SRuzMNUE8znxPpCEpRZQeYh9GdkC8rZAGn35tqnfu7oBd6t363ucVYksyBqE8jWDQBrEHpn5Q13GLy4yT3H5GZc6v8J39biAu7TDah91SppYyRZh8rYfMqNrMjuWdUsLXf92y15VuAV9Dgu2veSqVs",
                "pub_key": "0090ae2232412a9526894d228e63b026868bb98a0e5ac39c20a0dccdc8f795ca2d",
                "priv_key": "58d6ce2c3a72ecfaa74a3ef356ecc3e31d72c65386f136e0126361d7c02e725f924802834f14c7484ab476d00bf194fd9cb42ad8a55b0c903bcf8521784945a6",
                "chain_code": "754a9eb5e7a29d6859c404edbf590dee4ea8a9c8fdda160ff912f047f0a1269e",
                "parent_fprint": "eea02584",
            },
            # m/0'/1/2'/2
            {
                "path": "m/0'/1/2'/2",
                "index": 2,
                "ex_pub": "xpub6DufbckoEMxZ4y6uPaVFdRngqGm8n9wUBZT17U18UFJHVUJ6MeGo9F2FMxo6mPXX75tVFhox6wm5m4sVuHugY9xg894Ad3m5CyGfAemaiU6",
                "ex_priv": "xprv3SaaZFM1Fe7osYzxP25WXJnNqnymW2LCFNio9J3qDeH3AVe1GsoA4peTSYx56A48NppJzhX4smrABpgut1s6h7ZLSs8mh4t5ijk3FRUSi7dZVfDza3LfDhtC9MxuhJwrq8uVGiXV8aYurk3pgYJjrxH",
                "pub_key": "0057515c161f6cba818e5d5b6956aafed3b918946c59db5637e82a58840e3b8d19",
                "priv_key": "d8a6948b9aeb8b1d18b4ed1d8a432cf76abf3fd42f98cd8231c9663ac22e725f1daf4570d537cbf155b57e323005eec8651c8a6204133f84200f54dfefb64910",
                "chain_code": "7fa351f22ff6b1d7a2f7d5bcaff17be5b9d9f7a38770425b87dd7e1725e42133",
                "parent_fprint": "330c1054",
            },
            # m/0'/1/2'/2/1000000000
            {
                "path": "m/0'/1/2'/2/1000000000",
                "index": 1000000000,
                "ex_pub": "xpub6HAbGZXeJUZU5U3U6K1dDpfZt4EJZT5ocnVEyiAmkWUfC7oScnwgDBvgVuJRTPQmSD7YsauSJHRx1f9CegMUdEACbpRMLPZacoCSKSqRfdr",
                "ex_priv": "xprv3TYhfXoij4E3BGZi8c3RRj26AnMiPQcDwzBWnHdqMneBsUYt4HZV7ss6uNyzhbJVWavFPr5TXimAyKKrsku4SePsnNw5MRaJGGpjtLCtV54PSAEzAtRekwLmPx7Q8SkpX4waimMWFX76sKPtS8wfCgq",
                "pub_key": "005f7576c04afd5cc602fd8e25228ee31f83f156b47c7dfcd94b50a0322aabf583",
                "priv_key": "70e17ad2d629acb9500cdb899fce121e74402e73ab8afc8947865b98c22e725fcfb410fa2dabd9b1ee9975fb0964e16a0371ad4f35c285b830ffd214dcf050fd",
                "chain_code": "c17727ab677b6d8060485e7d1fdf96ac5b9ef287fb91beacf6db019dcada5af3",
                "parent_fprint": "ee35fd25",
            },
        ],
    },
    {
        "seed": b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "curve_type": EllipticCurveTypes.ED25519_KHOLAW,
        "master": {
            "index": 0,
            "ex_pub": "xpub661MyMwAqRbcFkJT4ooNX5cdbj7LrcXKzMeebV2T3RvtDMKRhYKuFbGnidL49QyuiUZfNsdTwYpAB5dTWwvGGGNMt4Ef5a1wdf9vhmAVZ2R",
            "ex_priv": "xprv3QESAWYc9vDdZdB29wcbC5yGQZGVo2f6CpoqEX1jsUvMvtvdPh78PsP4QFS5cUobzWGi5VQ876WtUiJMDv1FPaDtqi1qvuCV2wMqsNerwWPuwGNYPuxmVS8fNqtVhCU1JTuPcxtvyvUGtricXijZ28z",
            "pub_key": "00b129d3115af42af9fed2f610958f64f8b1731909fdb28773e2aad006b5d79cc7",
            "priv_key": "101cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4052ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
            "chain_code": "78fe3dbc48c922324d02156f4d0b6508ede14c9bb62a5b542223ac8fa5745953",
            "parent_fprint": "00000000",
        },
        "der_paths": [
            # m/0
            {
                "path": "m/0",
                "index": 0,
                "ex_pub": "xpub67tsdC92p67EGQnoUhHjiVTGpmfFpPkrw1RdQMPEFsewSPKhWeHwyH2NXQ7XBZnwPLidv6TtLTfwMT2LAzWM5oQeSSjXqS7gxtAy9roXwEA",
                "ex_priv": "xprv3QnxzvwipTK89zE7NCHjnt1Y1QzhMhC4Y1Zq156FTKwrPU4iRidDxLLpUGhWy3qXfQY1ydMMnwBuWSuuyS93bVdcVZDWhnTzupvpji8y9V1hbjKqeuRq7rNo4gcx8MNEBAJ1xPZvXscaUiwg5Sqjf58",
                "pub_key": "003ba44fcc951e764bdafc2f56fcecf710c08817277386f9d20bd519bd48df0abf",
                "priv_key": "c0118293fc269db1b5df4b5904deb8ef6eb2c0cd184c198a4317464224ab40528db4861a969864cc3915e901b2103c5c15d45176504e27c945fdbccada2d2c39",
                "chain_code": "0c583578e39679489d895162d015375913db9cccf585c946b5d663b381497176",
                "parent_fprint": "00e1a47c",
            },
            # m/0/2147483647'
            {
                "path": "m/0/2147483647'",
                "index": Bip32KeyIndex.HardenIndex(2147483647),
                "ex_pub": "xpub6BK1R6c8X3p6cYK4pLP65jyeJf7BAWtVHHGquLMCgRdUwB86iJ9B7QXhiiYJUpJ1cjqifb7sEHhMme7ccVgQFH4qGb6ajrpvmEihk9mCQVP",
                "ex_priv": "xprv3RopmtTqXHz4JrFGe9vMvnaVXixtpG6xkAWj5ULZJkhVzyuBiTkU4PFJNJv9BTz54vZ4JjcvDrLi8AJhtPffSmRup75JPFrwyu7RLbFbSpSojMDrik7pLNEzMG9JKe4MbSjeFHmW7fqWwZquKKsaYks",
                "pub_key": "00ef835a17b037cf8cd2a2489096cd9873b6a94706aa3d9f0ad603b884994a8e3f",
                "priv_key": "d89c292cb8073ff8e7027c49b69ae66b3e8e85d4d0f50e67f64080c928ab4052727b02c5ba8c12cdbd95f107cdd9be572cfa9a3adb3e35adf3af739b969b932d",
                "chain_code": "07cc242e4340750b183ba703d73b3ca49aa6ef035932fd661e23edf541c5e65c",
                "parent_fprint": "d1a59029",
            },
            # m/0/2147483647'/1
            {
                "path": "m/0/2147483647'/1",
                "index": 1,
                "ex_pub": "xpub6DLHn2nosGvvH4B3Kn47FXJxpc6vEhenWTQDzg3pZxzcqSPV3zhHmezp3PHTdiqm6aCGzjgyXEGYHaMF9djhwa21XJao7SSkKbiPSDf5NS8",
                "ex_priv": "xprv3SQfVqakFwKwSK2ABCxmNGpngCW7rmgor6Xey3bLd9KCs9QZdB16rWYKBv6YE5SnXK9Ec2tPUHZE8tzbUmqpKSSY3ponua1DpN652RFygjMgtvRf9egkRK9DjtberziiXmvHv9shhSucJLXaxoCDgs5",
                "pub_key": "00071a0ccec2390a2aed290aaab0c2cce89863fc60386f6aec54b9327260324829",
                "priv_key": "a82fc48a79e1c13345eb17c48addd040be20641b65486cb9870b63a82fab4052d366fe78a4204dfe4dfc4f16d15c55aafb2eb6675438c56aa77884176c85d6b8",
                "chain_code": "00ad9b5fab68c99ad553726fae8f1889037988c288bf43f1952d844f4313c141",
                "parent_fprint": "e4c19ac0",
            },
            # m/0/2147483647'/1/2147483646'
            {
                "path": "m/0/2147483647'/1/2147483646'",
                "index": Bip32KeyIndex.HardenIndex(2147483646),
                "ex_pub": "xpub6ECTQ5hL3S8cGvGSQHMGXVJEJWeJ4BJFDHDivxnMEDG1RmtaUNa2omjT18GrWFZBLMPWeeLGKkK6ntZg1MoY1aaiWxQSdWYq8fuCBch44hK",
                "ex_priv": "xprv3SfZqT6N3cHJv4sBcLACTarEhypYYLMqVvg72oMEUcnQnD4owSY5bZAkb2CR3tFVfnjjHpoafXGvZxn8ehgwauwdnnCmFqWkTgr7s2cE4qvvLpvCKns2XVo2AnxTfe69YyXDSN8m5An1DRHnxp1aehL",
                "pub_key": "00c9836566991a6d91f0a990d15f05c7cb560c4126232998028e2bfc031ed374f8",
                "priv_key": "b869ff3dc100cfb37f18658ca7bcb71e778e0422a37f912a8df0409533ab40524f8b2ed57b1e9004e64e0e08921495952cf4654b164c70d42e36bb4d6d935fca",
                "chain_code": "d07fd3e133f9a8326d97ad07f979628894a887eaba33b7fb23aaabbe081c9b73",
                "parent_fprint": "5a6e48da",
            },
            # m/0/2147483647'/1/2147483646'/2
            {
                "path": "m/0/2147483647'/1/2147483646'/2",
                "index": 2,
                "ex_pub": "xpub6H1kzEddddfVn4GrDmV2NEpa4LT6y7k7F7YRKfaCAFP6kCMdhzLZqmEJpMDkjHCNydyQTAB1sthzD4Hm9enNChQW62ZqbfXVhrnHdsJdUMR",
                "ex_priv": "xprv3TW5V8MJpZGMpgNupeujRsivuinNnsfMQQcoDEnZZwiFWkiJsCyyx7nLds5yHyLXuzTEVKCM6EeU6jZq385S2osfRYKipBv84Dg1kpnx2E9T4xusB7Y2KixEFHvXF2YeQTuiJ112oE8d67mYUatcYcq",
                "pub_key": "0003136dcfbc7cacea009cc071afd300385f158ab958b2085da41018b4a6870049",
                "priv_key": "780e9e94417b363be7bd19d7c69fc011482089e5b67293a8313248cc39ab4052e343dd5764a5f5fe9be81e262e7888d783bdc72bc88054e897dca2231cfe1ce3",
                "chain_code": "a83b350fd471da44a3e113c203a3abe62702595de8fb3a73b293dcb0c7716ebc",
                "parent_fprint": "d97e190a",
            },
        ],
    },
]

# Tests for public derivation from extended key
TEST_VECT_PUBLIC_DER_EX_KEY = {
    "ex_pub": "xpub661MyMwAqRbcFkJT4ooNX5cdbj7LrcXKzMeebV2T3RvtDMKRhYKuFbGnidP9thFCKmuTe58Pa3uTGiwqU1UedwDrEeXLpMNukEnfN9GudgR",
    "ex_priv": "xprv3QESAWYc9vDdZdB29wcbC5yGQZGVo2f6CpoqEX1jsUvMvtvdPh78PsP4QFSbxud7NHczo1pQXVLaYhUppnjdGA2b8y5iBqjDECyghRYs6TSvMtX4taZvzdChaJjNZzwFhAGL8fNGAjQt9ssFc4oiYq1",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "ex_pub": "xpub69Dx86u91nSZVTDAp7WpMLMB8oWBttyTVKdfGRvt8jVXtU4YbK8zRgJtocDYKMXzW4E9eRLNuSt4gc9wkYyq8rXRzNrhAhZQAHZg83PuBx7",
        },
        # m/0/0
        {
            "index": 0,
            "ex_pub": "xpub6Ax5xZReRpZ2xtZYpPZeWbUnPCSJP2DjLMWUd9n9NY3hk88Azqthum2SgpZqd5keKXnBPnArNH5nVrWfHtRMg1CiFLw3zsn8joiuGQ2KUb3",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Tests for public derivation from public key
TEST_VECT_PUBLIC_DER_PUB_KEY = {
    "pub_key": "00b83340567ccea3de6c12c76fb2574bd68ecd8560f825632a0fb066ec149fe7e3",
    "priv_key": "141cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4052ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
    "der_paths": [
        # m/0
        {
            "index": 0,
            "pub_key": "008af88531ce3daaad84ed0b776c2b17c43a77561caa5d187f669531dc4c5bbadc",
        },
        # m/0/0
        {
            "index": 0,
            "pub_key": "00483c4c636ac73f9b743e502605960f4c6302c629610530b682cf4ae0a73e20d2",
        },
        # m/0/0/0' : shall trigger an exception
        {
            "index": Bip32KeyIndex.HardenIndex(0),
        },
    ],
}

# Tests for invalid extended key
TEST_VECT_EX_KEY_ERR = [
    # Private keys with invalid lengths (generated on purpose to have a correct checksum)
    "4kvFa64nRVFDDHiwNiYwSpXvmk9FQ8Pb8gJKzNZbamwF3WJWCc4VNFn597dK9bQnZmf5s6uLs3q4gDgzmR2XcYWjC5f2tZoZSQ5qT7KwbHSggeqq8weEK89JQ4n69nxdrsWBCdZPNjKNy6BAi8LLpGBwRV",
    "2GCPTCdQMgwbuwZxuUM2PYHJGV2SixbNaSE7smT8aWe8grqhzh5GZR9S6YoY24HYxJmQbd2mGnAc8Toinp1PwgM8aesXCo6sX8WFRXvmpzfN7AX2A8DsnA3k7kZZpy4da4D6A9VZLKnZWWYgnH5k74r5vqJNq",
    # Private key with invalid net version
    "MEzTXWQJybqHGrjeUf9rH4YQSKywUAY7U1W4kzG4HwtGmHGP3jGoAWDbrK911j3v1wak9jVmP5ARbGPHVuCf3veptPAV9F7Jg47mvS19NYL4Gghmgo3jiwxoLZfM6KJjvv7LKHFbGBvQASc3yiFkcDCyfQC",
    # Private key with invalid secret byte (0x01 instead of 0x00, generated on purpose)
    "xprv3QESAWYc9vDdZdB29wcbC5yGQZGVo2f6CpoqEX1jsUvMvtvdPh78PsP4QG26WJ3XQL1ScacXSfxnwo3HJmVm5TZ4BbMAg1dmfSXZicw2yCmPXmviXBNRCqf8DvfWdH18jhNUuKXS6Xfnj9QASuppVU3",
    # Invalid master key (fingerprint is not valid)
    "xprv3QESAWYh7GuSp6t5HCXfEn9UQagmejaQrFr7iLdsAAAUXofxConN31M8VA1nH7876jDHeFB5RToJS35ANufW3YxgJLt95uFtpeZcwM8PEaBZAJdfBii5RVtq8Mx1MMCgeJFLSvZj2gVkqDQZ5RidWPK",
    # Invalid master key (index is not zero)
    "xprv3QESAWYc9vDdaP62JNBrhJ438z25Teym4p4HP1RGMnofbq5sfWW2SwEtqLpV9kMYfLQ75FGFd7N8o9SiK1nNj85AsfivtcKwqWoDsfcJ7nbyZN4kgBuekgmhW6jGFbPWCq7fWwHq2Qz8wFs6BVjmg1p",
    # Public keys with invalid lengths (generated on purpose to have a correct checksum)
    "Deb7pNXSbX7qSvc2eKsdGN2SihvPLednHE2tRn1NfAyWv7Z9S15B8NbeDNMoBNXwgVdvpWHJgDhhFs3QPPT69a2exFNc3GjttfhJtf7YRBZwxT",
    "5FQT7TT6bZmQ6QjZkc6823oZfymNGYGrzdynrpA9AwChPwj2q3WgL1wGRdQGgnjanFAdeysCYadDccspWxQ92vD7382KiKEcvTzwhoqrYKwC8xdhP",
]


#
# Tests
#
class Bip32KholawEd25519Tests(Bip32BaseTests):
    # Tets supported derivation
    def test_supported_derivation(self):
        self.assertTrue(Bip32KholawEd25519.IsPublicDerivationSupported())

    # Run all tests in test vector using FromSeed for construction and ChildKey for derivation
    def test_from_seed_with_child_key(self):
        self._test_from_seed_with_child_key(Bip32KholawEd25519, TEST_VECT)

    # Run all tests in test vector using FromSeed for construction and DerivePath for derivation
    def test_from_seed_with_derive_path(self):
        self._test_from_seed_with_derive_path(Bip32KholawEd25519, TEST_VECT)

    # Run all tests in test vector using FromSeedAndPath for construction
    def test_from_seed_and_path(self):
        self._test_from_seed_and_path(Bip32KholawEd25519, TEST_VECT)

    # Run all tests in test vector using FromExtendedKey for construction
    def test_from_ex_key(self):
        self._test_from_ex_key(Bip32KholawEd25519, TEST_VECT)

    # Run all tests in test vector using FromPrivateKey for construction
    def test_from_priv_key(self):
        self._test_from_priv_key(Bip32KholawEd25519, TEST_VECT)

    # Run all tests in test vector using FromPublicKey for construction
    def test_from_pub_key(self):
        self._test_from_pub_key(Bip32KholawEd25519, TEST_VECT)

    # Test public derivation from extended key
    def test_public_derivation_ex_key(self):
        self._test_public_derivation_ex_key(Bip32KholawEd25519, TEST_VECT_PUBLIC_DER_EX_KEY)

    # Test public derivation from public key
    def test_public_derivation_pub_key(self):
        self._test_public_derivation_pub_key(Bip32KholawEd25519, TEST_VECT_PUBLIC_DER_PUB_KEY)

    # Test elliptic curve
    def test_elliptic_curve(self):
        self._test_elliptic_curve(Bip32KholawEd25519, EllipticCurveTypes.ED25519_KHOLAW)

    # Test invalid extended key
    def test_invalid_ex_key(self):
        self._test_invalid_ex_key(Bip32KholawEd25519, TEST_VECT_EX_KEY_ERR)

    # Test invalid seed
    def test_invalid_seed(self):
        self._test_invalid_seed(Bip32KholawEd25519, b"\x00" * (Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN - 1))

    # Test old class
    def test_old_cls(self):
        self.assertTrue(Bip32Ed25519Kholaw is Bip32KholawEd25519)
