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

"""Module for Monero mnemonic encoding."""

# Imports
from abc import ABC
from typing import List

from bip_utils.monero.mnemonic.monero_entropy_generator import MoneroEntropyGenerator
from bip_utils.monero.mnemonic.monero_mnemonic import MoneroLanguages, MoneroMnemonic
from bip_utils.monero.mnemonic.monero_mnemonic_utils import MoneroMnemonicUtils, MoneroWordsListGetter
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase, MnemonicUtils


class MoneroMnemonicEncoderBase(MnemonicEncoderBase, ABC):
    """
    Monero mnemonic encoder base class.
    It encodes bytes to the mnemonic phrase.
    """

    m_lang: MoneroLanguages

    def __init__(self,
                 lang: MoneroLanguages = MoneroLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        super().__init__(lang, MoneroWordsListGetter)
        self.m_lang = lang

    def _EncodeToList(self,
                      entropy_bytes: bytes) -> List[str]:
        """
        Encode bytes to list of mnemonic words.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            list[str]: List of encoded mnemonic words

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not MoneroEntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Consider 4 bytes at a time, 4 bytes represent 3 words
        mnemonic = []
        for i in range(len(entropy_bytes) // 4):
            mnemonic += MnemonicUtils.BytesChunkToWords(entropy_bytes[i * 4:(i * 4) + 4], self.m_words_list, "little")

        return mnemonic


class MoneroMnemonicNoChecksumEncoder(MoneroMnemonicEncoderBase):
    """
    Monero mnemonic encoder class (no checksum).
    It encodes bytes to the mnemonic phrase without checksum.
    """

    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase (no checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Encoded mnemonic (no checksum)

        Raises:
            ValueError: If entropy is not valid
        """
        return MoneroMnemonic.FromList(self._EncodeToList(entropy_bytes))


class MoneroMnemonicWithChecksumEncoder(MoneroMnemonicEncoderBase):
    """
    Monero mnemonic encoder class (with checksum).
    It encodes bytes to the mnemonic phrase with checksum.
    """

    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase (with checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Encoded mnemonic (with checksum)

        Raises:
            ValueError: If entropy is not valid
        """
        words = self._EncodeToList(entropy_bytes)
        checksum_word = MoneroMnemonicUtils.ComputeChecksum(words, self.m_lang)

        return MoneroMnemonic.FromList(words + [checksum_word])


class MoneroMnemonicEncoder:
    """
    Monero mnemonic encoder class.
    Helper class to encode bytes to the mnemonic phrase with or without checksum.
    """

    m_no_chk_enc: MoneroMnemonicNoChecksumEncoder
    m_with_chk_enc: MoneroMnemonicWithChecksumEncoder

    def __init__(self,
                 lang: MoneroLanguages = MoneroLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.m_no_chk_enc = MoneroMnemonicNoChecksumEncoder(lang)
        self.m_with_chk_enc = MoneroMnemonicWithChecksumEncoder(lang)

    def EncodeNoChecksum(self,
                         entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase (no checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Encoded mnemonic (no checksum)

        Raises:
            ValueError: If bytes length is not valid
        """
        return self.m_no_chk_enc.Encode(entropy_bytes)

    def EncodeWithChecksum(self,
                           entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase (with checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            Mnemonic object: Encoded mnemonic (with checksum)

        Raises:
            ValueError: If bytes length is not valid
        """
        return self.m_with_chk_enc.Encode(entropy_bytes)
