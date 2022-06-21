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

"""
Module for Electrum mnemonic decoding.
Reference: https://github.com/electrum/py-electrum-sdk
"""

# Imports
from typing import Optional, Union
from bip_utils.electrum.mnemonic.electrum_mnemonic import ElectrumMnemonicConst, ElectrumLanguages, ElectrumMnemonic
from bip_utils.electrum.mnemonic.electrum_mnemonic_utils import ElectrumMnemonicUtils
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListFinder, Bip39WordsListGetter
from bip_utils.utils.misc import IntegerUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicDecoderBase


class ElectrumMnemonicDecoder(MnemonicDecoderBase):
    """
    Electrum mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    def __init__(self,
                 lang: Optional[ElectrumLanguages] = ElectrumLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (ElectrumLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a ElectrumLanguages enum
            ValueError: If loaded words list is not valid
        """
        if lang is not None and not isinstance(lang, ElectrumLanguages):
            raise TypeError("Language is not an enumerative of ElectrumLanguages")
        super().__init__(lang.value if lang is not None else lang,
                         Bip39WordsListFinder,
                         Bip39WordsListGetter)

    def Decode(self,
               mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to bytes (no checksum).

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_obj = ElectrumMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in ElectrumMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Check mnemonic validity:
        if not ElectrumMnemonicUtils.IsValidMnemonic(mnemonic_obj):
            raise ValueError("Invalid mnemonic")

        # Get words
        words = mnemonic_obj.ToList()
        # Detect language if it was not specified at construction
        words_list, _ = self._FindLanguage(mnemonic_obj)

        # Decode words
        n = words_list.Length()
        entropy_int = 0
        for word in reversed(words):
            entropy_int = (entropy_int * n) + words_list.GetWordIdx(word)

        return IntegerUtils.ToBytes(entropy_int)
