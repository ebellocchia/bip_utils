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
Module for Electrum mnemonic encoding.
Reference: https://github.com/spesmilo/electrum
"""

# Imports
import math
from bip_utils.electrum.mnemonic.electrum_entropy_generator import ElectrumEntropyGenerator
from bip_utils.electrum.mnemonic.electrum_mnemonic import ElectrumLanguages, ElectrumMnemonicTypes, ElectrumMnemonic
from bip_utils.electrum.mnemonic.electrum_mnemonic_utils import ElectrumMnemonicUtils
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase


class ElectrumMnemonicEncoder(MnemonicEncoderBase):
    """
    Electrum mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    m_mnemonic_type: ElectrumMnemonicTypes

    def __init__(self,
                 mnemonic_type: ElectrumMnemonicTypes,
                 lang: ElectrumLanguages = ElectrumLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            mnemonic_type (ElectrumMnemonicTypes): Mnemonic type
            lang (ElectrumLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a ElectrumLanguages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, ElectrumLanguages):
            raise TypeError("Language is not an enumerative of ElectrumLanguages")
        super().__init__(lang.value, Bip39WordsListGetter)
        self.m_mnemonic_type = mnemonic_type

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
        entropy_int = BytesUtils.ToInteger(entropy_bytes)
        entropy_bit_len = math.floor(math.log(entropy_int, 2))
        if not ElectrumEntropyGenerator.IsValidEntropyBitLen(entropy_bit_len):
            raise ValueError(f"Entropy bit length ({entropy_bit_len}) is not valid")

        # Encode to words
        n = self.m_words_list.Length()
        mnemonic = []
        while entropy_int > 0:
            word_idx = entropy_int % n
            entropy_int //= n
            mnemonic.append(self.m_words_list.GetWordAtIdx(word_idx))

        # Check if the mnemonic is valid
        mnemonic = ElectrumMnemonic.FromList(mnemonic)
        if not ElectrumMnemonicUtils.IsValidMnemonicType(mnemonic, self.m_mnemonic_type):
            raise ValueError("Entropy bytes are not suitable for generating a valid mnemonic")

        import binascii
        print(binascii.hexlify(entropy_bytes))

        return mnemonic
