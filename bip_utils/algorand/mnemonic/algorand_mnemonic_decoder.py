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
Module for Algorand mnemonic decoding.
Reference: https://github.com/algorand/py-algorand-sdk
"""

# Imports
from typing import Optional, Union

from bip_utils.algorand.mnemonic.algorand_mnemonic import AlgorandLanguages, AlgorandMnemonic, AlgorandMnemonicConst
from bip_utils.algorand.mnemonic.algorand_mnemonic_utils import AlgorandMnemonicUtils
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListFinder, Bip39WordsListGetter
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicChecksumError, MnemonicDecoderBase, MnemonicWordsList


class AlgorandMnemonicDecoder(MnemonicDecoderBase):
    """
    Algorand mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    def __init__(self,
                 lang: Optional[AlgorandLanguages] = AlgorandLanguages.ENGLISH) -> None:
        """
        Construct class.
        Language is set to English by default because Algorand mnemonic only support one language,
        so it's useless (and slower) to automatically detect the language.

        Args:
            lang (AlgorandLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a AlgorandLanguages enum
            ValueError: If loaded words list is not valid
        """
        if lang is not None and not isinstance(lang, AlgorandLanguages):
            raise TypeError("Language is not an enumerative of AlgorandLanguages")
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
        mnemonic_obj = AlgorandMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in AlgorandMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Get words
        words = mnemonic_obj.ToList()
        # Detect language if it was not specified at construction
        words_list, _ = self._FindLanguage(mnemonic_obj)

        # Get words indexes
        word_indexes = [words_list.GetWordIdx(w) for w in words]
        # Get back entropy as list
        entropy_list = AlgorandMnemonicUtils.ConvertBits(word_indexes[:-1], 11, 8)
        # Cannot be None if the number of words is valid (checked at the beginning)
        assert entropy_list is not None
        # Get back entropy bytes
        entropy_bytes = BytesUtils.FromList(entropy_list)[:-1]

        # Validate checksum
        self.__ValidateChecksum(entropy_bytes, word_indexes[-1], words_list)

        return entropy_bytes

    @staticmethod
    def __ValidateChecksum(entropy_bytes: bytes,
                           chksum_word_idx_exp: int,
                           words_list: MnemonicWordsList) -> None:
        """
        Validate a mnemonic checksum.

        Args:
            entropy_bytes (list)          : Entropy bytes
            chksum_word_idx_exp (int)     : Expected checksum word index
            words_list (MnemonicWordsList): Words list

        Raises:
            MnemonicChecksumError: If checksum is not valid
        """
        chksum_word_idx = AlgorandMnemonicUtils.ComputeChecksumWordIndex(entropy_bytes)
        if chksum_word_idx != chksum_word_idx_exp:
            raise MnemonicChecksumError(
                f"Invalid checksum (expected {words_list.GetWordAtIdx(chksum_word_idx)}, "
                f"got {words_list.GetWordAtIdx(chksum_word_idx_exp)})"
            )
