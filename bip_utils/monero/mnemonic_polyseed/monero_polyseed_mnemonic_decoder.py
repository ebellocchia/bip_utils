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

"""Module for Monero Polyseed mnemonic decoding."""

# Imports
from typing import Optional, Union

from typing_extensions import override

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListFinder, Bip39WordsListGetter
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedCoins,
    MoneroPolyseedLanguages,
    MoneroPolyseedMnemonic,
    MoneroPolyseedMnemonicConst,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_utils import (
    MoneroPolyseedDecodedData,
    MoneroPolyseedGf,
    MoneroPolyseedMnemonicUtils,
)
from bip_utils.utils.mnemonic import (
    Mnemonic,
    MnemonicChecksumError,
    MnemonicDecoderBase,
)


class MoneroPolyseedMnemonicDecoder(MnemonicDecoderBase):
    """
    Monero Polyseed mnemonic decoder class.
    It decodes a 16-word mnemonic phrase to polyseed data.
    """

    m_coin: MoneroPolyseedCoins

    def __init__(self,
                 coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO,
                 lang: Optional[MoneroPolyseedLanguages] = None) -> None:
        """
        Construct class.

        Args:
            coin (MoneroPolyseedCoins, optional)    : Coin for domain separation (default: MONERO)
            lang (MoneroPolyseedLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a MoneroPolyseedLanguages enum
            ValueError: If loaded words list is not valid
        """
        if lang is not None and not isinstance(lang, MoneroPolyseedLanguages):
            raise TypeError("Language is not a MoneroPolyseedLanguages enum")
        super().__init__(lang.value if lang is not None else lang,
                         Bip39WordsListFinder,
                         Bip39WordsListGetter)
        self.m_coin = coin

    @override
    def Decode(self,
               mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to secret bytes (19 bytes).

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded secret bytes (19 bytes)

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        return self.DecodeWithData(mnemonic).secret

    def DecodeWithData(self,
                       mnemonic: Union[str, Mnemonic]) -> MoneroPolyseedDecodedData:
        """
        Decode a mnemonic phrase to full polyseed data.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            MoneroPolyseedDecodedData: Decoded polyseed data

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_obj = MoneroPolyseedMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in MoneroPolyseedMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list, _ = self._FindLanguage(mnemonic_obj)

        # Convert words to polynomial coefficients
        words = mnemonic_obj.ToList()
        coeffs = [words_list.GetWordIdx(w) for w in words]

        # Undo coin domain separation
        coeffs[MoneroPolyseedMnemonicConst.POLY_NUM_CHECK_DIGITS] ^= int(self.m_coin)

        # Verify checksum
        if not MoneroPolyseedGf.PolyCheck(coeffs):
            raise MnemonicChecksumError("Invalid Polyseed checksum")

        # Extract data
        return MoneroPolyseedMnemonicUtils.PolyToData(coeffs)
