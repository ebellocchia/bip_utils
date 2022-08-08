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

"""Module for Electrum v1 mnemonic generation."""

# Imports
from typing import Dict, Union

from bip_utils.electrum.mnemonic_v1.electrum_v1_entropy_generator import (
    ElectrumV1EntropyBitLen, ElectrumV1EntropyGenerator
)
from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic import (
    ElectrumV1Languages, ElectrumV1MnemonicConst, ElectrumV1WordsNum
)
from bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder import ElectrumV1MnemonicEncoder
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumV1MnemonicGeneratorConst:
    """Class container for Electrum v1 mnemonic generator constants."""

    # Entropy length for each words number
    WORDS_NUM_TO_ENTROPY_LEN: Dict[ElectrumV1WordsNum, ElectrumV1EntropyBitLen] = {
        ElectrumV1WordsNum.WORDS_NUM_12: ElectrumV1EntropyBitLen.BIT_LEN_128,
    }


class ElectrumV1MnemonicGenerator:
    """
    Electrum v1 mnemonic generator class.
    It generates 12-words mnemonic in according to v1 Electrum mnemonic.
    """

    m_mnemonic_encoder: ElectrumV1MnemonicEncoder

    def __init__(self,
                 lang: ElectrumV1Languages = ElectrumV1Languages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (ElectrumV1Languages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a ElectrumV1Languages enum
            ValueError: If language words list is not valid
        """
        self.m_mnemonic_encoder = ElectrumV1MnemonicEncoder(lang)

    def FromWordsNumber(self,
                        words_num: Union[int, ElectrumV1WordsNum]) -> Mnemonic:
        """
        Generate mnemonic with the specified words number from random entropy.
        There is no really need of this method, since the words number can only be 12, but it's
        kept to have the same usage of Bip39/Monero mnemonic generator.

        Args:
            words_num (int or ElectrumV1WordsNum): Number of words (12)

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid
        """

        # Check words number
        if words_num not in ElectrumV1MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        # Convert int to enum if necessary
        if isinstance(words_num, int):
            words_num = ElectrumV1WordsNum(words_num)

        # Get entropy length in bit from words number
        entropy_bit_len = ElectrumV1MnemonicGeneratorConst.WORDS_NUM_TO_ENTROPY_LEN[words_num]
        # Generate entropy
        entropy_bytes = ElectrumV1EntropyGenerator(entropy_bit_len).Generate()

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
