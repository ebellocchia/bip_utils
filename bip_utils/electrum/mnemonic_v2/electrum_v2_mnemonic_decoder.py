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
Module for Electrum v2 mnemonic decoding.
Reference: https://github.com/electrum/py-electrum-sdk
"""

# Imports
from typing import Optional, Union

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListFinder, Bip39WordsListGetter
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import (
    ElectrumV2Languages, ElectrumV2Mnemonic, ElectrumV2MnemonicConst, ElectrumV2MnemonicTypes
)
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_utils import ElectrumV2MnemonicUtils
from bip_utils.utils.misc import IntegerUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicDecoderBase


class ElectrumV2MnemonicDecoder(MnemonicDecoderBase):
    """
    Electrum v2 mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    m_mnemonic_type: Optional[ElectrumV2MnemonicTypes]

    def __init__(self,
                 mnemonic_type: Optional[ElectrumV2MnemonicTypes] = None,
                 lang: Optional[ElectrumV2Languages] = None) -> None:
        """
        Construct class.

        Args:
            mnemonic_type (ElectrumV2MnemonicTypes, optional): Mnemonic type, None for all types
            lang (ElectrumV2Languages, optional)             : Language, None for automatic detection

        Raises:
            TypeError: If the language is not a ElectrumV2Languages enum
            ValueError: If loaded words list is not valid
        """
        if mnemonic_type is not None and not isinstance(mnemonic_type, ElectrumV2MnemonicTypes):
            raise TypeError("Mnemonic type is not an enumerative of ElectrumV2MnemonicTypes")
        if lang is not None and not isinstance(lang, ElectrumV2Languages):
            raise TypeError("Language is not an enumerative of ElectrumV2Languages")
        super().__init__(lang.value if lang is not None else lang,
                         Bip39WordsListFinder,
                         Bip39WordsListGetter)
        self.m_mnemonic_type = mnemonic_type

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
        mnemonic_obj = ElectrumV2Mnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in ElectrumV2MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Check mnemonic validity:
        if not ElectrumV2MnemonicUtils.IsValidMnemonic(mnemonic_obj, self.m_mnemonic_type):
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
