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

"""Module for Monero mnemonic generation."""

# Imports
from typing import Dict, Union

from bip_utils.monero.mnemonic.monero_entropy_generator import MoneroEntropyBitLen, MoneroEntropyGenerator
from bip_utils.monero.mnemonic.monero_mnemonic import MoneroLanguages, MoneroMnemonicConst, MoneroWordsNum
from bip_utils.monero.mnemonic.monero_mnemonic_encoder import MoneroMnemonicEncoder
from bip_utils.utils.mnemonic import Mnemonic


class MoneroMnemonicGeneratorConst:
    """Class container for Monero mnemonic generator constants."""

    # Entropy length for each words number
    WORDS_NUM_TO_ENTROPY_LEN: Dict[MoneroWordsNum, MoneroEntropyBitLen] = {
        MoneroWordsNum.WORDS_NUM_12: MoneroEntropyBitLen.BIT_LEN_128,
        MoneroWordsNum.WORDS_NUM_13: MoneroEntropyBitLen.BIT_LEN_128,
        MoneroWordsNum.WORDS_NUM_24: MoneroEntropyBitLen.BIT_LEN_256,
        MoneroWordsNum.WORDS_NUM_25: MoneroEntropyBitLen.BIT_LEN_256,
    }


class MoneroMnemonicGenerator:
    """
    Monero mnemonic generator class.
    Mnemonic can be generated randomly from words number or from a specified entropy.
    """

    m_mnemonic_encoder: MoneroMnemonicEncoder

    def __init__(self,
                 lang: MoneroLanguages = MoneroLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If language words list is not valid
        """
        self.m_mnemonic_encoder = MoneroMnemonicEncoder(lang)

    def FromWordsNumber(self,
                        words_num: Union[int, MoneroWordsNum]) -> Mnemonic:
        """
        Generate mnemonic with the specified words number from random entropy.

        Args:
            words_num (int or MoneroWordsNum): Number of words (12, 13, 24, 25)

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid
        """

        # Check words number
        if words_num not in MoneroMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        # Convert int to enum if necessary
        if isinstance(words_num, int):
            words_num = MoneroWordsNum(words_num)

        # Get entropy length in bit from words number
        entropy_bit_len = MoneroMnemonicGeneratorConst.WORDS_NUM_TO_ENTROPY_LEN[words_num]
        # Generate entropy
        entropy_bytes = MoneroEntropyGenerator(entropy_bit_len).Generate()

        return (self.FromEntropyWithChecksum(entropy_bytes)
                if words_num in MoneroMnemonicConst.MNEMONIC_WORD_NUM_CHKSUM
                else self.FromEntropyNoChecksum(entropy_bytes))

    def FromEntropyNoChecksum(self,
                              entropy_bytes: bytes) -> Mnemonic:
        """
        Generate mnemonic from the specified entropy bytes (no checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Generated mnemonic (no checksum)

        Raises:
            ValueError: If entropy byte length is not valid
        """
        return self.m_mnemonic_encoder.EncodeNoChecksum(entropy_bytes)

    def FromEntropyWithChecksum(self,
                                entropy_bytes: bytes) -> Mnemonic:
        """
        Generate mnemonic from the specified entropy bytes (with checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Generated mnemonic (with checksum)

        Raises:
            ValueError: If entropy byte length is not valid
        """
        return self.m_mnemonic_encoder.EncodeWithChecksum(entropy_bytes)
