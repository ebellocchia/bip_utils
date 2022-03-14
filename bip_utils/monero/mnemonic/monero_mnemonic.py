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

"""Module for Monero mnemonic decoding/encoding."""

# Imports
import os
from enum import auto, IntEnum, unique
from typing import Dict, List, Optional, Union, Tuple
from bip_utils.monero.mnemonic.monero_mnemonic_ex import MoneroMnemonicChecksumError
from bip_utils.monero.mnemonic.monero_entropy_generator import MoneroEntropyGenerator
from bip_utils.utils.misc import BytesUtils, CryptoUtils, IntegerUtils
from bip_utils.utils.mnemonic import (
    MnemonicWordsList, MnemonicLanguages, Mnemonic, MnemonicWordsListGetterBase
)


@unique
class MoneroWordsNum(IntEnum):
    """Enumerative for Monero words number."""

    WORDS_NUM_12 = 12   # No checksum
    WORDS_NUM_13 = 13   # With checksum
    WORDS_NUM_24 = 24   # No checksum
    WORDS_NUM_25 = 25   # With checksum


@unique
class MoneroLanguages(MnemonicLanguages):
    """Enumerative for Monero languages."""

    CHINESE_SIMPLIFIED = auto()
    DUTCH = auto()
    ENGLISH = auto()
    FRENCH = auto()
    GERMAN = auto()
    ITALIAN = auto()
    JAPANESE = auto()
    PORTUGUESE = auto()
    SPANISH = auto()
    RUSSIAN = auto()


class MoneroMnemonicConst:
    """Class container for Monero mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[MoneroWordsNum] = [
        MoneroWordsNum.WORDS_NUM_12,
        MoneroWordsNum.WORDS_NUM_13,
        MoneroWordsNum.WORDS_NUM_24,
        MoneroWordsNum.WORDS_NUM_25,
    ]

    # Mnemonic word numbers with checksum
    MNEMONIC_WORD_NUM_CHKSUM: List[MoneroWordsNum] = [
        MoneroWordsNum.WORDS_NUM_13,
        MoneroWordsNum.WORDS_NUM_25,
    ]

    # Language unique prefix lengths
    LANGUAGE_UNIQUE_PREFIX_LEN: Dict[MoneroLanguages, int] = {
        MoneroLanguages.CHINESE_SIMPLIFIED: 1,
        MoneroLanguages.DUTCH: 4,
        MoneroLanguages.ENGLISH: 3,
        MoneroLanguages.FRENCH: 4,
        MoneroLanguages.GERMAN: 4,
        MoneroLanguages.ITALIAN: 4,
        MoneroLanguages.JAPANESE: 4,
        MoneroLanguages.PORTUGUESE: 4,
        MoneroLanguages.SPANISH: 4,
        MoneroLanguages.RUSSIAN: 4,
    }

    # Language files
    LANGUAGE_FILES: Dict[MoneroLanguages, str] = {
        MoneroLanguages.CHINESE_SIMPLIFIED: "monero_words/chinese_simplified.txt",
        MoneroLanguages.DUTCH: "monero_words/dutch.txt",
        MoneroLanguages.ENGLISH: "monero_words/english.txt",
        MoneroLanguages.FRENCH: "monero_words/french.txt",
        MoneroLanguages.GERMAN: "monero_words/german.txt",
        MoneroLanguages.ITALIAN: "monero_words/italian.txt",
        MoneroLanguages.JAPANESE: "monero_words/japanese.txt",
        MoneroLanguages.PORTUGUESE: "monero_words/portuguese.txt",
        MoneroLanguages.SPANISH: "monero_words/spanish.txt",
        MoneroLanguages.RUSSIAN: "monero_words/russian.txt",
    }

    # Total number of words
    WORDS_LIST_NUM: int = 1626


class MoneroMnemonic(Mnemonic):
    """Monero mnemonic class (alias for Mnemonic)."""


class _MoneroWordsListGetter(MnemonicWordsListGetterBase):
    """
    Monero words list getter class.
    It allows to get words list by language so that they are loaded from file only once per language.
    """

    def GetByLanguage(self,
                      lang: MnemonicLanguages) -> MnemonicWordsList:
        """
        Get words list by language.
        Words list of a specific language are loaded from file only the first time they are requested.

        Args:
            lang (MnemonicLanguages): Language

        Returns:
            MnemonicWordsList object: MnemonicWordsList object

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, MoneroLanguages):
            raise TypeError("Language is not an enumerative of MoneroLanguages")

        # Only load words list for a specific language the first time it is requested
        try:
            return self.m_words_lists[lang]
        except KeyError:
            self.m_words_lists[lang] = self._LoadWordsList(self.__GetLanguageFile(lang),
                                                           MoneroMnemonicConst.WORDS_LIST_NUM)

            return self.m_words_lists[lang]

    @staticmethod
    def __GetLanguageFile(lang: MoneroLanguages) -> str:
        """
        Get the specified language file name.

        Args:
            lang (MoneroLanguages): Language

        Returns:
            str: Language file name
        """
        return os.path.join(os.path.dirname(__file__),
                            MoneroMnemonicConst.LANGUAGE_FILES[lang])


class _MoneroWordsListFinder:
    """
    Monero words list finder class.
    It automatically finds the correct words list from a mnemonic.
    """

    @staticmethod
    def FindLanguage(mnemonic: Mnemonic) -> Tuple[MnemonicWordsList, MoneroLanguages]:
        """
        Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.

        Args:
            mnemonic (Mnemonic object): Mnemonic object

        Returns:
           MnemonicWordsList object: MnemonicWordsList object

        Raises:
            ValueError: If the mnemonic language cannot be found
        """

        for lang in MoneroLanguages:
            # Search all the words because some languages have words in common
            # (e.g. 'fatigue' both in English and French)
            # It's more time consuming, but considering only the first word can detect the wrong language sometimes
            try:
                words_list = _MoneroWordsListGetter.Instance().GetByLanguage(lang)
                for word in mnemonic.ToList():
                    words_list.GetWordIdx(word)
                return words_list, lang
            except ValueError:
                continue

        # Language not found
        raise ValueError(f"Invalid language for mnemonic '{mnemonic.ToStr()}'")


class _MoneroMnemonicUtils:
    """Utility functions for Monero mnemonic."""

    @staticmethod
    def ComputeChecksum(mnemonic: List[str],
                        lang: MoneroLanguages) -> str:
        """
        Compute checksum.

        Args:
            mnemonic (list)       : Mnemonic list of words
            lang (MoneroLanguages): Language

        Returns:
            str: Checksum word
        """
        unique_prefix_len = MoneroMnemonicConst.LANGUAGE_UNIQUE_PREFIX_LEN[lang]

        # Join the prefix of all words together
        prefixes = "".join(word[:unique_prefix_len] for word in mnemonic)

        return mnemonic[CryptoUtils.Crc32(prefixes) % len(mnemonic)]


class MoneroMnemonicEncoder:
    """
    Monero mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    m_lang: MoneroLanguages
    m_words_list: MnemonicWordsList

    def __init__(self,
                 lang: MoneroLanguages) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages): Language

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.m_lang = lang
        self.m_words_list = _MoneroWordsListGetter.Instance().GetByLanguage(lang)

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
        words = self.__EncodeToList(entropy_bytes)

        return MoneroMnemonic.FromList(words)

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
        words = self.__EncodeToList(entropy_bytes)

        # Compute checksum word
        checksum_word = _MoneroMnemonicUtils.ComputeChecksum(words, self.m_lang)

        return MoneroMnemonic.FromList(words + [checksum_word])

    def __EncodeToList(self,
                       entropy_bytes: bytes) -> List[str]:
        """
        Encode bytes to list of mnemonic words.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            List: List of encoded mnemonic words

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not MoneroEntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Consider 4 bytes at a time, 4 bytes represent 3 words
        words = []
        for i in range(len(entropy_bytes) // 4):
            words += self.__BytesChunkToWords(entropy_bytes[i * 4:(i * 4) + 4])

        return words

    def __BytesChunkToWords(self,
                            bytes_chunk: bytes) -> List[str]:
        """
        Get words from a bytes chunk.

        Args:
            bytes_chunk (bytes): Bytes chunk

        Returns:
            Tuple: 3 word indexes
        """
        n = MoneroMnemonicConst.WORDS_LIST_NUM

        int_chunk = BytesUtils.ToInteger(bytes_chunk, endianness="little")

        word1_idx = int_chunk % n
        word2_idx = ((int_chunk // n) + word1_idx) % n
        word3_idx = ((int_chunk // n // n) + word2_idx) % n

        return [self.m_words_list.GetWordAtIdx(w) for w in (word1_idx, word2_idx, word3_idx)]


class MoneroMnemonicDecoder:
    """
    Monero mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    m_lang: Optional[MoneroLanguages]
    m_words_list: Optional[MnemonicWordsList]

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[MoneroLanguages] = None) -> None:
        """
        Construct class.

        Args:
            lang (MoneroLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.m_lang = lang
        self.m_words_list = (_MoneroWordsListGetter.Instance().GetByLanguage(lang)
                             if lang is not None
                             else None)

    def Decode(self,
               mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to bytes (no checksum).

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes

        Raises:
            MoneroMnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_obj = MoneroMnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in MoneroMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list, lang = (_MoneroWordsListFinder.FindLanguage(mnemonic_obj)
                            if self.m_words_list is None
                            else (self.m_words_list, self.m_lang))

        assert isinstance(lang, MoneroLanguages)

        # Get words
        words = mnemonic_obj.ToList()

        # Validate checksum
        self.__ValidateChecksum(mnemonic_obj, lang)

        # Consider 3 words at a time, 3 words represent 4 bytes
        entropy_bytes = b""

        for i in range(len(words) // 3):
            word1, word2, word3 = words[i * 3:(i * 3) + 3]
            entropy_bytes += self.__WordsToBytesChunk(word1, word2, word3, words_list)

        return entropy_bytes

    @staticmethod
    def __ValidateChecksum(mnemonic_obj: Mnemonic,
                           lang: MoneroLanguages) -> None:
        """
        Validate a mnemonic checksum.

        Args:
            mnemonic_obj (Mnemonic object): Mnemonic object
            lang (MoneroLanguages)        : Language

        Raises:
            MoneroMnemonicChecksumError: If checksum is not valid
        """
        if mnemonic_obj.WordsCount() in MoneroMnemonicConst.MNEMONIC_WORD_NUM_CHKSUM:
            words = mnemonic_obj.ToList()
            chksum_word = _MoneroMnemonicUtils.ComputeChecksum(words[:-1], lang)
            if words[-1] != chksum_word:
                raise MoneroMnemonicChecksumError(f"Invalid checksum (expected {chksum_word}, got {words[-1]})")

    @staticmethod
    def __WordsToBytesChunk(word1: str,
                            word2: str,
                            word3: str,
                            words_list: MnemonicWordsList) -> bytes:
        """
        Get bytes chunk from words.

        Args:
            word1 (str)                          : Word 1
            word2 (str)                          : Word 2
            word3 (str)                          : Word 3
            words_list (MnemonicWordsList object): Mnemonic list

        Returns:
            bytes: Bytes chunk
        """
        n = MoneroMnemonicConst.WORDS_LIST_NUM

        # Get the word indexes
        word1_idx = words_list.GetWordIdx(word1)
        word2_idx = words_list.GetWordIdx(word2) % n
        word3_idx = words_list.GetWordIdx(word3) % n

        # Get back the bytes chunk
        bytes_chunk = word1_idx + (n * ((word2_idx - word1_idx) % n)) + (n * n * ((word3_idx - word2_idx) % n))

        return IntegerUtils.ToBytes(bytes_chunk, bytes_num=4, endianness="little")
