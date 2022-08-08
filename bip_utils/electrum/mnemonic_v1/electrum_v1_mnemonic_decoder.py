# Copyright (c) 2022 Emanuele Bellocchia
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
Module for Electrum v1 mnemonic decoding.
Reference: https://github.com/spesmilo/electrum
"""

# Imports
from typing import Optional, Union

from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic import (
    ElectrumV1Languages, ElectrumV1Mnemonic, ElectrumV1MnemonicConst
)
from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils import (
    ElectrumV1WordsListFinder, ElectrumV1WordsListGetter
)
from bip_utils.utils.mnemonic import Mnemonic, MnemonicDecoderBase, MnemonicUtils


class ElectrumV1MnemonicDecoder(MnemonicDecoderBase):
    """
    Electrum v1 mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    def __init__(self,
                 lang: Optional[ElectrumV1Languages] = ElectrumV1Languages.ENGLISH) -> None:
        """
        Construct class.
        Language is set to English by default because Electrum v1 mnemonic only support one language,
        so it's useless (and slower) to automatically detect the language.

        Args:
            lang (ElectrumV1Languages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a ElectrumV1Languages enum
            ValueError: If loaded words list is not valid
        """
        super().__init__(lang, ElectrumV1WordsListFinder, ElectrumV1WordsListGetter)

    def Decode(self,
               mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to bytes.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes

        Raises:
            ValueError: If mnemonic is not valid
        """
        mnemonic_obj = ElectrumV1Mnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in ElectrumV1MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list, _ = self._FindLanguage(mnemonic_obj)

        # Get words
        words = mnemonic_obj.ToList()

        # Consider 3 words at a time, 3 words represent 4 bytes
        entropy_bytes = b""
        for i in range(len(words) // 3):
            word1, word2, word3 = words[i * 3:(i * 3) + 3]
            entropy_bytes += MnemonicUtils.WordsToBytesChunk(word1, word2, word3, words_list, "big")

        return entropy_bytes
