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
Module for Algorand mnemonic encoding.
Reference: https://github.com/algorand/py-algorand-sdk
"""

# Imports
from typing import List

from bip_utils.algorand.mnemonic.algorand_entropy_generator import AlgorandEntropyGenerator
from bip_utils.algorand.mnemonic.algorand_mnemonic import AlgorandLanguages, AlgorandMnemonic
from bip_utils.algorand.mnemonic.algorand_mnemonic_utils import AlgorandMnemonicUtils
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase


class AlgorandMnemonicEncoder(MnemonicEncoderBase):
    """
    Algorand mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    def __init__(self,
                 lang: AlgorandLanguages = AlgorandLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (AlgorandLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a AlgorandLanguages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, AlgorandLanguages):
            raise TypeError("Language is not an enumerative of AlgorandLanguages")
        super().__init__(lang.value, Bip39WordsListGetter)

    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            Mnemonic object: Encoded mnemonic

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not AlgorandEntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Compute checksum word
        chksum_word_idx = AlgorandMnemonicUtils.ComputeChecksumWordIndex(entropy_bytes)
        # Convert entropy bytes to a list of word indexes
        word_indexes = AlgorandMnemonicUtils.ConvertBits(entropy_bytes, 8, 11)
        # Cannot be None by converting bytes from 8-bit to 11-bit
        assert word_indexes is not None
        # Get mnemonic
        return AlgorandMnemonic.FromList(self.__IndexesToWords(word_indexes + [chksum_word_idx]))

    def __IndexesToWords(self,
                         indexes: List[int]) -> List[str]:
        """
        Get a list of words from a list of indexes.

        Args:
            indexes (list[int]): List of indexes

        Returns:
            list[str]: List of words
        """
        return [self.m_words_list.GetWordAtIdx(idx) for idx in indexes]
