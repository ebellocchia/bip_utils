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
Module for Electrum v2 mnemonic encoding.
Reference: https://github.com/spesmilo/electrum
"""

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter

# Imports
from bip_utils.electrum.mnemonic_v2.electrum_v2_entropy_generator import ElectrumV2EntropyGenerator
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import (
    ElectrumV2Languages, ElectrumV2Mnemonic, ElectrumV2MnemonicTypes
)
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_utils import ElectrumV2MnemonicUtils
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase


class ElectrumV2MnemonicEncoder(MnemonicEncoderBase):
    """
    Electrum v2 mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    m_mnemonic_type: ElectrumV2MnemonicTypes

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
            ValueError: If loaded words list is not valid
        """
        if not isinstance(mnemonic_type, ElectrumV2MnemonicTypes):
            raise TypeError("Mnemonic type is not an enumerative of ElectrumV2MnemonicTypes")
        if not isinstance(lang, ElectrumV2Languages):
            raise TypeError("Language is not an enumerative of ElectrumV2Languages")
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
            ValueError: If bytes length is not valid or a mnemonic cannot be generated
        """

        # Check entropy length
        entropy_int = BytesUtils.ToInteger(entropy_bytes)
        if not ElectrumV2EntropyGenerator.AreEntropyBitsEnough(entropy_int):
            raise ValueError("Entropy bit length is not enough for generating a valid mnemonic")

        # Encode to words
        n = self.m_words_list.Length()
        mnemonic = []
        while entropy_int > 0:
            word_idx = entropy_int % n
            entropy_int //= n
            mnemonic.append(self.m_words_list.GetWordAtIdx(word_idx))

        # Check if the mnemonic is valid
        mnemonic_obj = ElectrumV2Mnemonic.FromList(mnemonic)
        if not ElectrumV2MnemonicUtils.IsValidMnemonic(mnemonic_obj, self.m_mnemonic_type):
            raise ValueError("Entropy bytes are not suitable for generating a valid mnemonic")

        return mnemonic_obj
