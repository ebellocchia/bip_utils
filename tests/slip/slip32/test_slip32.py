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
import unittest

from bip_utils import (
    Bip32PathParser, Bip32Slip10Secp256k1, Bip39SeedGenerator, Slip32KeyDeserializer, Slip32PrivateKeySerializer,
    Slip32PublicKeySerializer
)


# Tests from SLIP32 page
# https://github.com/satoshilabs/slips/blob/master/slip-0032.md
TEST_VECT = [
    {
        "path": "m",
        "ex_pub": "xpub1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuq7eqte474swq3cvvvcncumfz6xe6l0j6jdl990an7mukyyuemsyjszuwypl",
        "ex_priv": "xprv1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuqqcxlqmar3fjhkprndzkpnp2xlze76g4hu7g7c4r4r2m2e6y8xlvu566tn6",
    },
    {
        "path": "m/0",
        "ex_pub": "xpub1qyqqqqqqurn9qwkq2l84m3mwqu672mw5f5vnkt57yuwv94rtcavunxczrc7qxa4l2v75k923p75lgyjtdeyxzmc8m6709mcvlvv9ehz22aj9pdr4m6lwmk",
        "ex_priv": "xprv1qyqqqqqqurn9qwkq2l84m3mwqu672mw5f5vnkt57yuwv94rtcavunxczrc7qpw4gn29a6cw9ug4e7yrqrkrerj0cl39jlfkln45dxdhsavpmqm4krfqykk",
    },
    {
        "path": "m/1",
        "ex_pub": "xpub1qyqqqqqpt3yfzltg8zmxdt43r6k8cnuclqrh0x6hcafzuwzsjuv7av085kfq963xfxe4z2u6skdtvk9gtc5cnfaw8xe9rzrhktwq726yk7za27ydw88adn",
        "ex_priv": "xprv1qyqqqqqpt3yfzltg8zmxdt43r6k8cnuclqrh0x6hcafzuwzsjuv7av085kfqpsd74lcvfkucgec2grrfc228h8fne4lkuayuvlsledwxzxxa5y5zefalyg",
    },
    {
        "path": "m/0'",
        "ex_pub": "xpub1qxqqqqqq78qr7hlewyyfzt74vasa87k63pu7g9e6hfzlzrdyh0v5k8zfw9sqylcasaesu3swjgdnsgjzjy2kt0unmteqs8kkskewm5wsz9mt9sfuvlxj6p",
        "ex_priv": "xprv1qxqqqqqq78qr7hlewyyfzt74vasa87k63pu7g9e6hfzlzrdyh0v5k8zfw9sqpsyv7vcejeyzcpkm85jel7vmujlhpquzf4f3sh3nry0w0n4jh7t0jhc039",
    },
    {
        "path": "m/1'",
        "ex_pub": "xpub1qxqqqqqpg0xyhjjecen2taujv52gzfvq9mfva3rd78zu4rn2qkx6k5j6w0cs8dgcfffxmtr2hk3a34222s28rn5rarpzvr2kwps98cncpy3rr867k5u83k",
        "ex_priv": "xprv1qxqqqqqpg0xyhjjecen2taujv52gzfvq9mfva3rd78zu4rn2qkx6k5j6w0csq0hs9lznqqr59zgleyz93w57mjpk8k837fn7xf43q7r3p37mxn095hysnx",
    },
    {
        "path": "m/44'/0'/0'",
        "ex_pub": "xpub1qwqqqqpvsqqqqqyqqqqqq0dyhsvs5f5qzywnr7klmjg972nldnnhcmcsnyv3zme984p5g5seqdm5eyg0eurl495gd6nefux4etke4l3sk39c8alzzwae9ycw0h6t6ltmssr",
        "ex_priv": "xprv1qwqqqqpvsqqqqqyqqqqqq0dyhsvs5f5qzywnr7klmjg972nldnnhcmcsnyv3zme984p5g5seqrlxftuztddhs42vxw3gkgcgtlqg9a53k0r39nqafenwzvef0k585enml6g",
    },
    {
        "path": "m/44'/0'/1'",
        "ex_pub": "xpub1qwqqqqpvsqqqqqyqqqqqz2t3lgkmpl6ad8skdfqxsya28k0dp8z2mtpwpn3n2g7633tqna85qfwsycv984xr5du3vra4r5hjv2kxfejjryfenqkyugvqhnh35geajlgxhp0",
        "ex_priv": "xprv1qwqqqqpvsqqqqqyqqqqqz2t3lgkmpl6ad8skdfqxsya28k0dp8z2mtpwpn3n2g7633tqna85qzy9th76xllxvwllcqfkvxzsfc7t6lveyy6xp880vxguw2fnn4wx2mhtjy8",
    },
    {
        "path": "m/44'/2'/0'",
        "ex_pub": "xpub1qwqqqqpvsqqqqq5qqqqqpp5u2pz7tlrcjert40x3jcd3qx7rre6lu5xl3fv9c7dsth9q436cqdq0uwuw3yt9yk96cr9hz9snccvdrtmrmsep4y9h28gxjucpgsducuj4f9r",
        "ex_priv": "xprv1qwqqqqpvsqqqqq5qqqqqpp5u2pz7tlrcjert40x3jcd3qx7rre6lu5xl3fv9c7dsth9q436cqzvre5gd352pvzcshxjtkceq062c2p22xyekr82hk782n4d2xprdysp4gxc",
    },
    {
        "path": "m/49'/0'/0'",
        "ex_pub": "xpub1qwqqqqp3sqqqqqyqqqqqqm42udj6urs2p24cgvjule7dwmpmjzgrt7yfulflrwz84xs8jlktqtclx3ufrvs0w45w4clvnp5lh7m8hj4k7dvrymcsanzzx44a2kfe6xynfgh",
        "ex_priv": "xprv1qwqqqqp3sqqqqqyqqqqqqm42udj6urs2p24cgvjule7dwmpmjzgrt7yfulflrwz84xs8jlktqzyq65t490dyryrq0cretzxn7ezdj6l6qdzxhn5neh0a50z2n8r7vumvllf",
    },
    {
        "path": "m/49'/2'/0'",
        "ex_pub": "xpub1qwqqqqp3sqqqqq5qqqqqqeahu8w9cu9fx5zzrrx0grz844rdf2wgtqvkxakwp6zn4jnmupycq2c88z9a9mdt50q29sy9vut06lyevhfp97e8xmmmjf040kfzky9vu2pu92u",
        "ex_priv": "xprv1qwqqqqp3sqqqqq5qqqqqqeahu8w9cu9fx5zzrrx0grz844rdf2wgtqvkxakwp6zn4jnmupycqr8jytxzuztsf8lzefmxymqecln68muhrv0kgx2htz4neqeyv070gg6dcn7",
    },
    {
        "path": "m/84'/0'/0'",
        "ex_pub": "xpub1qwqqqqz5sqqqqqyqqqqqqjjn5z4jrwwujkrfcn5j59s3jnsrcrhnlagpftrf9apnc3m9fy8uqfc85cha4npxa2dk8vwpj7gx74hwqxqdp083jehp5tdrfa0n5zdfkg3lp00",
        "ex_priv": "xprv1qwqqqqz5sqqqqqyqqqqqqjjn5z4jrwwujkrfcn5j59s3jnsrcrhnlagpftrf9apnc3m9fy8uqrs57f6dzm9qmygrrwvtzcnpspsaqwfslgup4ak5et6ykqvpn2mdggeaxrp",
    },
]

# Tests for invalid extended keys
TEST_VECT_EX_KEY_INVALID = [
    # Invalid net version
    "xprw1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuqqcxlqmar3fjhkprndzkpnp2xlze76g4hu7g7c4r4r2m2e6y8xlvu566tn6",
    # Private key with invalid secret byte (0x01 instead of 0x00, generated on purpose)
    "xprv1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuqgcxlqmar3fjhkprndzkpnp2xlze76g4hu7g7c4r4r2m2e6y8xlvufdeu4a",
]

# Test mnemonic
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


#
# Tests
#
class Slip32Tests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        seed_bytes = Bip39SeedGenerator(TEST_MNEMONIC).Generate()
        bip32_mst_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
        for test in TEST_VECT:
            bip32_ctx = bip32_mst_ctx.DerivePath(test["path"])
            # Test extended public key
            self.__test_ex_pub(test["ex_pub"], test["path"], bip32_ctx.ChainCode(), bip32_ctx)
            self.__test_ex_pub(test["ex_pub"], Bip32PathParser.Parse(test["path"]), bip32_ctx.ChainCode(), bip32_ctx)
            self.__test_ex_pub(test["ex_pub"], test["path"], bip32_ctx.ChainCode().ToBytes(), bip32_ctx)
            # Test extended private key
            self.__test_ex_priv(test["ex_priv"], test["path"], bip32_ctx.ChainCode(), bip32_ctx)
            self.__test_ex_priv(test["ex_priv"], Bip32PathParser.Parse(test["path"]), bip32_ctx.ChainCode(), bip32_ctx)
            self.__test_ex_priv(test["ex_priv"], test["path"], bip32_ctx.ChainCode().ToBytes(), bip32_ctx)

    # Test invalid extended keys
    def test_invalid_ex_keys(self):
        for test in TEST_VECT_EX_KEY_INVALID:
            self.assertRaises(ValueError, Slip32KeyDeserializer.DeserializeKey, test)

    # Test extended public key
    def __test_ex_pub(self, test_ex_pub, test_path, test_chain_code, bip32_ctx):
        # Test serializer
        ex_pub = Slip32PublicKeySerializer.Serialize(bip32_ctx.PublicKey().KeyObject(),
                                                     test_path,
                                                     test_chain_code)
        self.assertEqual(test_ex_pub, ex_pub)
        # Test deserializer
        deser_key = Slip32KeyDeserializer.DeserializeKey(ex_pub)
        self.assertEqual(bip32_ctx.PublicKey().RawCompressed().ToBytes(), deser_key.KeyBytes())
        self.assertEqual(test_path if isinstance(test_path, str) else test_path.ToStr(), deser_key.Path().ToStr())
        self.assertEqual(bip32_ctx.ChainCode().ToBytes(), deser_key.ChainCode().ToBytes())
        self.assertTrue(deser_key.IsPublic())

    # Test extended private key
    def __test_ex_priv(self, test_ex_priv, test_path, test_chain_code, bip32_ctx):
        # Test serializer
        ex_priv = Slip32PrivateKeySerializer.Serialize(bip32_ctx.PrivateKey().KeyObject(),
                                                       test_path,
                                                       test_chain_code)
        self.assertEqual(test_ex_priv, ex_priv)
        # Test deserializer
        deser_key = Slip32KeyDeserializer.DeserializeKey(ex_priv)
        self.assertEqual(bip32_ctx.PrivateKey().Raw().ToBytes(), deser_key.KeyBytes())
        self.assertEqual(test_path if isinstance(test_path, str) else test_path.ToStr(), deser_key.Path().ToStr())
        self.assertEqual(bip32_ctx.ChainCode().ToBytes(), deser_key.ChainCode().ToBytes())
        self.assertFalse(deser_key.IsPublic())
