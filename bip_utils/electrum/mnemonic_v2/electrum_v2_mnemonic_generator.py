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

"""Module for Electrum v2 mnemonic generation."""

# Imports
from typing import Dict, Union

from bip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator import (
    ElectrumV2EntropyBitLen, ElectrumV2EntropyGenerator
)
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import (
    ElectrumV2Languages, ElectrumV2MnemonicConst, ElectrumV2MnemonicTypes, ElectrumV2WordsNum
)
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_encoder import ElectrumV2MnemonicEncoder
from bip_utils.utils.misc import BytesUtils, IntegerUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumV2MnemonicGeneratorConst:
    """Class container for Electrum v2 mnemonic generator constants."""

    # Entropy length for each words number
    WORDS_NUM_TO_ENTROPY_LEN: Dict[ElectrumV2WordsNum, ElectrumV2EntropyBitLen] = {
        ElectrumV2WordsNum.WORDS_NUM_12: ElectrumV2EntropyBitLen.BIT_LEN_132,
        ElectrumV2WordsNum.WORDS_NUM_24: ElectrumV2EntropyBitLen.BIT_LEN_264,
    }
    # Maximum number of attempts (just to avoid infinite looping)
    MAX_ATTEMPTS: int = 10**6


class ElectrumV2MnemonicGenerator:
    """
    Electrum v2 mnemonic generator class.
    It generates 12 or 24-words mnemonic in according to Electrum wallets.
    """

    m_mnemonic_encoder: ElectrumV2MnemonicEncoder

    def __init__(self,
                 mnemonic_type: ElectrumV2MnemonicTypes,
                 lang: ElectrumV2Languages = ElectrumV2Languages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            mnemonic_type (ElectrumV2MnemonicTypes): Mnemonic type
            lang (ElectrumV2Languages, optional)   : Language (default: English)

        Raises:
            TypeError: If the language is not a ElectrumV2Languages enum or
                       the mnemonic type is not a ElectrumV2MnemonicTypes enum
            ValueError: If language words list is not valid
        """
        self.m_mnemonic_encoder = ElectrumV2MnemonicEncoder(mnemonic_type, lang)

    def FromWordsNumber(self,
                        words_num: Union[int, ElectrumV2WordsNum]) -> Mnemonic:
        """
        Generate mnemonic with the specified words number and type from random entropy.

        Args:
            words_num (int or ElectrumV2WordsNum)  : Number of words (12)

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If words number is not valid
        """

        # Check words number
        if words_num not in ElectrumV2MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        # Convert int to enum if necessary
        if isinstance(words_num, int):
            words_num = ElectrumV2WordsNum(words_num)

        # Get entropy length in bit from words number
        entropy_bit_len = ElectrumV2MnemonicGeneratorConst.WORDS_NUM_TO_ENTROPY_LEN[words_num]
        # Generate entropy
        entropy_bytes = ElectrumV2EntropyGenerator(entropy_bit_len).Generate()

        return self.FromEntropy(entropy_bytes)

    def FromEntropy(self,
                    entropy_bytes: bytes) -> Mnemonic:
        """
        Generate mnemonic from the specified entropy bytes.
        Because of the mnemonic encoding algorithm used by Electrum, the specified entropy will only be a starting
        point to find a suitable one. Therefore, it's very likely that the actual entropy bytes will be different.
        To get the actual entropy bytes, just decode the generated mnemonic.
        Please note that, to successfully generate a mnemonic, the bits of the big endian integer encoded entropy
        shall be at least 121 (for 12 words) or 253 (for 24 words). Otherwise, a mnemonic generation is not possible
        and a ValueError exception will be raised.

        Args:
            entropy_bytes (bytes): Entropy bytes

        Returns:
            Mnemonic object: Generated mnemonic

        Raises:
            ValueError: If entropy byte length is not valid or a mnemonic cannot be generated
        """

        # Do not waste time trying if the entropy bit are not enough
        if ElectrumV2EntropyGenerator.AreEntropyBitsEnough(entropy_bytes):
            # Same of Electrum: increase the entropy until a valid one is found
            entropy_int = BytesUtils.ToInteger(entropy_bytes)
            for i in range(ElectrumV2MnemonicGeneratorConst.MAX_ATTEMPTS):
                new_entropy_int = entropy_int + i
                try:
                    return self.m_mnemonic_encoder.Encode(IntegerUtils.ToBytes(new_entropy_int))
                except ValueError:
                    continue

        raise ValueError("Unable to generate a valid mnemonic")
