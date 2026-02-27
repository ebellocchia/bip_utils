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
    Ton,
    TonAddrVersions,
    TonMnemonicGenerator,
    TonSeedGenerator,
    TonPrivateKey,
    TonPublicKey,
)


TEST_VECT = [
    {
        "mnemonic": "flash garden eagle south occur hair believe pigeon shell later awake evoke club bundle humble just alarm start shoe depth curve sadness coast cruel",
        "passphrase": "",
        "seed": b"6dca2b6bae5495c9b32ad0e21585893393f49593b46528cf4364e2ce3de9fbc4d5d260f6e64db115a3116e3bcde1eda36272ade47d5f458a1224f8a6b82c725d",
        "priv_key": "6dca2b6bae5495c9b32ad0e21585893393f49593b46528cf4364e2ce3de9fbc4",
        "pub_key": "00b20e72a472a091f2d6e5c8daae89acffc1725796ecfdecb91028473227cccd40",
        "address_v3r1": "UQBO7J5N3SRX5C36PjcLszc6mjtldjDO8399z2M_WFReD_Y6",
        "address_v3r2": "UQC4isU1Xv7IG26fVJW_EuJvfyPMdjio6U5AOX_1ItZMdvvY",
        "address_v4": "UQAL2-1_ypx8LjJq4kYrQCIHi4BiFoLzEtnoU6pnBxT0dlIW",
        "address_v5r1": "UQBnsrgS6CQgUrSPbSsH8E2NqeJu_jcHHc7UMBgCYYy42mCT",
        "address_def": "UQBnsrgS6CQgUrSPbSsH8E2NqeJu_jcHHc7UMBgCYYy42mCT",
    },
    {
        "mnemonic": "trip rude dry sand ahead pole spice knife lobster spider rather canyon caution catalog design process awesome garage coil climb daughter assault grab latin",
        "passphrase": "",
        "seed": b"bdeeedc743b2e0c7235b45b2247de18c7982f6f484c551ff21034cc761668e8513e53b519f187d5939d319525be16250890caa7ecc4781b8884c9eb444d2bcb6",
        "priv_key": "bdeeedc743b2e0c7235b45b2247de18c7982f6f484c551ff21034cc761668e85",
        "pub_key": "007b3a7c45f3889e7fcffa79f9508b1f0d4eb3e8e127f5e954e5b7b8c8bf3df2ac",
        "address_v3r1": "UQCcn8mY71L7KdN0zZ34iQZBFmf8CEfS3sKMSXUHOhJt8hTC",
        "address_v3r2": "UQAN8uYVEct8z7bR7jaqONOvFX4hiNAqCOMEBClc0W-h3q6f",
        "address_v4": "UQDwRUWRenS3SdqOQlgzjXfh8pLmi6BHcycSRnjK356uEtmh",
        "address_v5r1": "UQDBXf5dtEWokmn7H9i8DGF1hlFW9C0FTPn1-Lu6TU3dCcU9",
        "address_def": "UQDBXf5dtEWokmn7H9i8DGF1hlFW9C0FTPn1-Lu6TU3dCcU9",
    },
    {
        "mnemonic": "one throw battle section gauge admit aware alarm shine van wreck record battle cancel advice kitten quote panther vault page degree march whisper truly",
        "passphrase": "test",
        "seed": b"00915030dbc91ca64e4384d6d1b743b50332d9741f60a844230d20dff5232708a714247a1ddc7b031ce0c414da40b156eefb968dc86b7b65c950a91f237d2ca9",
        "priv_key": "00915030dbc91ca64e4384d6d1b743b50332d9741f60a844230d20dff5232708",
        "pub_key": "0001da83e896f14a9ba71ba11b42199a2e814b64ef0f831c6b67d8ca31235da69c",
        "address_v3r1": "UQBkw9A2EJ3mQyZMgSlNjti0iGaNf3iDzXt6sgvHE6sBtZXP",
        "address_v3r2": "UQDANpdHk9f8kyosO62qczm3hYCWlPAE-w73lmEaoeLg2nnS",
        "address_v4": "UQD4YDreaPB9VdhnicmMet4Xta6CAVK_pF1M_4_MHk4okPUR",
        "address_v5r1": "UQBKpLgvvceEXGIH6IkzilTp5c0RPXYZWqq9G7ONVqc-lWPV",
        "address_def": "UQBKpLgvvceEXGIH6IkzilTp5c0RPXYZWqq9G7ONVqc-lWPV",
    },
]


#
# Tests
#
class TonTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            # Generate seed
            seed = TonSeedGenerator(test["mnemonic"], test["passphrase"]).Generate()
            self.assertEqual(test["seed"], binascii.hexlify(seed))

            # Test Ton class
            ton = Ton.FromSeed(seed)
            self.assertEqual(test["priv_key"], ton.PrivateKey().Raw().ToHex())
            self.assertEqual(test["pub_key"], ton.PublicKey().RawCompressed().ToHex())
            self.assertEqual(test["address_v3r1"], ton.GetAddress(TonAddrVersions.V3R1))
            self.assertEqual(test["address_v3r2"], ton.GetAddress(TonAddrVersions.V3R2))
            self.assertEqual(test["address_v4"], ton.GetAddress(TonAddrVersions.V4))
            self.assertEqual(test["address_v5r1"], ton.GetAddress(TonAddrVersions.V5R1))
            self.assertEqual(test["address_def"], ton.GetAddress())
