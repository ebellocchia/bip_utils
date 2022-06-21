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
Module for Electrum old mnemonic encoding.
Reference: https://github.com/spesmilo/electrum
"""

# Imports
from bip_utils.electrum.old_mnemonic.electrum_old_entropy_generator import ElectrumOldEntropyGenerator
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic import ElectrumOldLanguages, ElectrumOldMnemonic
from bip_utils.electrum.old_mnemonic.electrum_old_mnemonic_utils import ElectrumOldWordsListGetter
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase, MnemonicUtils


class ElectrumOldMnemonicEncoder(MnemonicEncoderBase):
    """
    ElectrumOld mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    def __init__(self,
                 lang: ElectrumOldLanguages = ElectrumOldLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (ElectrumOldLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a ElectrumOldLanguages enum
            ValueError: If loaded words list is not valid
        """
        super().__init__(lang, ElectrumOldWordsListGetter)

    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128)

        Returns:
            Mnemonic object: Encoded mnemonic

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not ElectrumOldEntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Build mnemonic
        mnemonic = []
        for i in range(len(entropy_bytes) // 4):
            mnemonic += MnemonicUtils.BytesChunkToWords(entropy_bytes[i * 4:(i * 4) + 4], self.m_words_list, "big")

        return ElectrumOldMnemonic.FromList(mnemonic)
