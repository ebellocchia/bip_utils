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

from bip_utils import SplToken
from bip_utils.solana.spl_token import SplTokenConst


# Test vector
TEST_VECT = [
    {
        "wallet_address": "E4m7DpaYjLp8Cw4oJbUYXEouXsb9KdX9WsMyPiDnqiV3",
        "token_mint_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "pda": "Cvfrz4PaK1bm7NCVX8ekRe9fK8fMKKAGF5twA4QiXwwv",
    },
    {
        "wallet_address": "E4m7DpaYjLp8Cw4oJbUYXEouXsb9KdX9WsMyPiDnqiV3",
        "token_mint_address": "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
        "pda": "7nBYto6bXvMLCVq1xuhdufHExQyMmHMGYo9581eikdui",
    },
    {
        "wallet_address": "E4m7DpaYjLp8Cw4oJbUYXEouXsb9KdX9WsMyPiDnqiV3",
        "token_mint_address": "9n4nbM75f5Ui33ZbPYXn59EwSgE8CGsHtAeTH5YFeJ9E",
        "pda": "FQJGuFzjSgMW5bgviE9VbM2Sm3DTJ4VcEgj5ayPYLGSU",
    },
    {
        "wallet_address": "GP5XXWmhT2UKetabxr57VSX9o9yWNtGYWykwUNiEhw74",
        "token_mint_address": "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
        "pda": "946AXpLByxxuw3teyGgYCcihVYfSPf13WTeLbem6LdAx",
    },
    {
        "wallet_address": "GP5XXWmhT2UKetabxr57VSX9o9yWNtGYWykwUNiEhw74",
        "token_mint_address": "EqWCKXfs3x47uVosDpTRgFniThL9Y8iCztJaapxbEaVX",
        "pda": "2RrmLGk8eT68BzivXqDFNP4QkHT34BemXC1YjMWJ493E",
    },
]


#
# Tests
#
class SplTokenTests(unittest.TestCase):
    # Test associated token address
    def test_associated_token_address(self):
        for test in TEST_VECT:
            pda = SplToken.GetAssociatedTokenAddress(test["wallet_address"], test["token_mint_address"])
            self.assertEqual(test["pda"], pda)

    # Test invalid parameters
    def test_invalid_params(self):
        # GetAssociatedTokenAddress
        self.assertRaises(ValueError,
                          SplToken.GetAssociatedTokenAddress,
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
                          "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb")
        self.assertRaises(ValueError,
                          SplToken.GetAssociatedTokenAddress,
                          "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb",
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh")
        # GetAssociatedTokenAddressWithProgramId
        self.assertRaises(ValueError,
                          SplToken.GetAssociatedTokenAddressWithProgramId,
                          "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb",
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh")
        self.assertRaises(ValueError,
                          SplToken.GetAssociatedTokenAddressWithProgramId,
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
                          "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb",
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh")
        self.assertRaises(ValueError,
                          SplToken.GetAssociatedTokenAddressWithProgramId,
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
                          "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
                          "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb")
        # FindPda
        self.assertRaises(ValueError, SplToken.FindPda, ["\x00" for _ in range(SplTokenConst.SEEDS_MAX_NUM + 1)], "")
        self.assertRaises(ValueError, SplToken.FindPda, ["\x00", "\x00" * 33, "\x00"], "")
        self.assertRaises(ValueError, SplToken.FindPda, ["\x00", "\x00"], "kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb")
