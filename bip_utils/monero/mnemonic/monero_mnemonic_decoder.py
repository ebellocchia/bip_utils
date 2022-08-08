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

"""Module for Monero mnemonic decoding."""

# Imports
from typing import List, Optional, Union

from bip_utils.monero.mnemonic.monero_mnemonic import MoneroLanguages, MoneroMnemonic, MoneroMnemonicConst
from bip_utils.monero.mnemonic.monero_mnemonic_utils import (
    MoneroMnemonicUtils, MoneroWordsListFinder, MoneroWordsListGetter
)
from bip_utils.utils.mnemonic import (
    Mnemonic, MnemonicChecksumError, MnemonicDecoderBase, MnemonicLanguages, MnemonicUtils
)


class MoneroMnemonicDecoder(MnemonicDecoderBase):
    """
    Monero mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[MoneroLanguages] = None) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        super().__init__(lang, MoneroWordsListFinder, MoneroWordsListGetter)

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
        mnemonic_obj = MoneroMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in MoneroMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list, lang = self._FindLanguage(mnemonic_obj)
        assert isinstance(lang, MoneroLanguages)

        # Get words
        words = mnemonic_obj.ToList()

        # Validate checksum
        self.__ValidateChecksum(words, lang)

        # Consider 3 words at a time, 3 words represent 4 bytes
        entropy_bytes = b""
        for i in range(len(words) // 3):
            word1, word2, word3 = words[i * 3:(i * 3) + 3]
            entropy_bytes += MnemonicUtils.WordsToBytesChunk(word1, word2, word3, words_list, "little")

        return entropy_bytes

    @staticmethod
    def __ValidateChecksum(words: List[str],
                           lang: MnemonicLanguages) -> None:
        """
        Validate a mnemonic checksum.

        Args:
            words (list[str])       : Words list
            lang (MnemonicLanguages): Language

        Raises:
            MnemonicChecksumError: If checksum is not valid
        """
        if len(words) in MoneroMnemonicConst.MNEMONIC_WORD_NUM_CHKSUM:
            chksum_word = MoneroMnemonicUtils.ComputeChecksum(words[:-1], lang)
            if words[-1] != chksum_word:
                raise MnemonicChecksumError(f"Invalid checksum (expected {chksum_word}, got {words[-1]})")
