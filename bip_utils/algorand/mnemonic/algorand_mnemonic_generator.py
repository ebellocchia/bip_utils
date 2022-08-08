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

"""Module for Algorand mnemonic generation."""

# Imports
from typing import Dict, Union

from bip_utils.algorand.mnemonic.algorand_entropy_generator import AlgorandEntropyBitLen, AlgorandEntropyGenerator
from bip_utils.algorand.mnemonic.algorand_mnemonic import AlgorandLanguages, AlgorandMnemonicConst, AlgorandWordsNum
from bip_utils.algorand.mnemonic.algorand_mnemonic_encoder import AlgorandMnemonicEncoder
from bip_utils.utils.mnemonic import Mnemonic


class AlgorandMnemonicGeneratorConst:
    """Class container for Algorand mnemonic generator constants."""

    # Entropy length for each words number
    WORDS_NUM_TO_ENTROPY_LEN: Dict[AlgorandWordsNum, AlgorandEntropyBitLen] = {
        AlgorandWordsNum.WORDS_NUM_25: AlgorandEntropyBitLen.BIT_LEN_256,
    }


class AlgorandMnemonicGenerator:
    """
    Algorand mnemonic generator class.
    It generates 25-words mnemonic in according to Algorand wallets.
    """

    m_mnemonic_encoder: AlgorandMnemonicEncoder

    def __init__(self,
                 lang: AlgorandLanguages = AlgorandLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (AlgorandLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a AlgorandLanguages enum
            ValueError: If language words list is not valid
        """
        self.m_mnemonic_encoder = AlgorandMnemonicEncoder(lang)

    def FromWordsNumber(self,
                        words_num: Union[int, AlgorandWordsNum]) -> Mnemonic:
        """
        Generate mnemonic with the specified words number from random entropy.
        There is no really need of this method, since the words number can only be 25, but it's
        kept to have the same usage of Bip39/Monero mnemonic generator.

        Args:
            words_num (int or AlgorandWordsNum): Number of words (25)

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid
        """

        # Check words number
        if words_num not in AlgorandMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        # Convert int to enum if necessary
        if isinstance(words_num, int):
            words_num = AlgorandWordsNum(words_num)

        # Get entropy length in bit from words number
        entropy_bit_len = AlgorandMnemonicGeneratorConst.WORDS_NUM_TO_ENTROPY_LEN[words_num]
        # Generate entropy
        entropy_bytes = AlgorandEntropyGenerator(entropy_bit_len).Generate()

        return self.FromEntropy(entropy_bytes)

    def FromEntropy(self,
                    entropy_bytes: bytes) -> Mnemonic:
        """
        Generate mnemonic from the specified entropy bytes.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If entropy byte length is not valid
        """
        return self.m_mnemonic_encoder.Encode(entropy_bytes)
