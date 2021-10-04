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

# BIP-0039 reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

# Imports
from __future__ import annotations
import os
from enum import auto, Enum, IntEnum, unique
from typing import Dict, List, Optional, Union, Tuple
from bip_utils.monero.mnemonic.monero_mnemonic_ex import MoneroChecksumError
from bip_utils.monero.mnemonic.monero_entropy_generator import MoneroEntropyGenerator
from bip_utils.utils.misc import ConvUtils, CryptoUtils
from bip_utils.utils.mnemonic import (
    Mnemonic, MnemonicWordsList, MnemonicWordsListGetterBase
)


@unique
class MoneroWordsNum(IntEnum):
    """ Enumerative for Monero words number. """

    WORDS_NUM_12 = 12   # No checksum
    WORDS_NUM_13 = 13   # With checksum
    WORDS_NUM_24 = 24   # No checksum
    WORDS_NUM_25 = 25   # With checksum


@unique
class MoneroLanguages(Enum):
    """ Enumerative for Monero languages. """

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
    """ Class container for Monero constants. """

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

    # Languages supporting binary search
    LANGUAGE_BIN_SEARCH: Dict[MoneroLanguages, bool] = {
        MoneroLanguages.CHINESE_SIMPLIFIED: False,
        MoneroLanguages.DUTCH: True,
        MoneroLanguages.ENGLISH: True,
        MoneroLanguages.FRENCH: False,
        MoneroLanguages.GERMAN: False,
        MoneroLanguages.ITALIAN: True,
        MoneroLanguages.JAPANESE: False,
        MoneroLanguages.PORTUGUESE: False,
        MoneroLanguages.SPANISH: False,
        MoneroLanguages.RUSSIAN: False,
    }

    # Total number of words
    WORDS_LIST_NUM: int = 1626


class MoneroMnemonic(Mnemonic):
    """ Monero mnemonic class (alias for Mnemonic). """
    pass


class _MoneroWordsListGetter(MnemonicWordsListGetterBase):
    """ Monero words list getter class. It allows to get words list by language so that
    they are loaded from file only once per language (i.e. on the first request).
    """

    def GetByLanguage(self,
                      lang: MoneroLanguages) -> MnemonicWordsList:
        """ Get words list by language.
        Words list of a specific language are loaded from file only the first time they are requested.

        Args:
            lang (MoneroLanguages): Language

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
            file_name = os.path.join(os.path.dirname(__file__), MoneroMnemonicConst.LANGUAGE_FILES[lang])
            words_num = MoneroMnemonicConst.WORDS_LIST_NUM
            bin_search = MoneroMnemonicConst.LANGUAGE_BIN_SEARCH[lang]

            self.m_words_lists[lang] = self._LoadWordsList(file_name, words_num, bin_search)

            return self.m_words_lists[lang]


class _MoneroWordsListFinder:
    """ Monero words list finder class.
    It automatically finds the correct words list from a mnemonic.
    """

    @staticmethod
    def FindLanguage(mnemonic: MoneroMnemonic) -> Tuple[MnemonicWordsList, MoneroLanguages]:
        """ Automatically find the language of the specified mnemonic and
        get the correct MnemonicWordsList class for it.

        Args:
            mnemonic (MoneroMnemonic object): MoneroMnemonic object

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
    """ Utility functions for Monero mnemonic. """

    @staticmethod
    def ComputeChecksum(mnemonic: List[str],
                        lang: MoneroLanguages) -> str:
        """ Compute checksum.

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
    """ Monero mnemonic encoder class. It encodes bytes to the mnemonic phrase. """

    def __init__(self,
                 lang: MoneroLanguages) -> None:
        """ Construct class.

        Args:
            lang (MoneroLanguages): Language

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.lang = lang
        self.m_words_list = _MoneroWordsListGetter.Instance().GetByLanguage(lang)

    def EncodeNoChecksum(self,
                         entropy_bytes: bytes) -> MoneroMnemonic:
        """ Encode bytes to mnemonic phrase (no checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            MoneroMnemonic object: Encoded mnemonic (no checksum)

        Raises:
            ValueError: If bytes length is not valid
        """
        words = self.__EncodeToList(entropy_bytes)

        return MoneroMnemonic.FromList(words)

    def EncodeWithChecksum(self,
                           entropy_bytes: bytes) -> MoneroMnemonic:
        """ Encode bytes to mnemonic phrase (with checksum).

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 256)

        Returns:
            MoneroMnemonic object: Encoded mnemonic (with checksum)

        Raises:
            ValueError: If bytes length is not valid
        """
        words = self.__EncodeToList(entropy_bytes)

        # Compute checksum word
        checksum_word = _MoneroMnemonicUtils.ComputeChecksum(words, self.lang)

        return MoneroMnemonic.FromList(words + [checksum_word])

    def __EncodeToList(self,
                       entropy_bytes: bytes) -> List[str]:
        """ Encode bytes to list of mnemonic words.

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

        words = []
        n = MoneroMnemonicConst.WORDS_LIST_NUM

        # Consider 4 bytes at a time, 4 bytes represent 3 words
        for i in range(len(entropy_bytes) // 4):
            x = ConvUtils.BytesToInteger(entropy_bytes[(i*4):(i*4) + 4],
                                         endianness="little")
            # Compute words indexes
            w1_idx = x % n
            w2_idx = ((x // n) + w1_idx) % n
            w3_idx = ((x // n // n) + w2_idx) % n

            # Get words
            words += [self.m_words_list.GetWordAtIdx(w1_idx),
                      self.m_words_list.GetWordAtIdx(w2_idx),
                      self.m_words_list.GetWordAtIdx(w3_idx)]

        return words


class MoneroMnemonicDecoder:
    """ Monero mnemonic decoder class. It decodes a mnemonic phrase to bytes. """

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[MoneroLanguages] = None) -> None:
        """ Construct class.

        Args:
            lang (MoneroLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a MoneroLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.lang = lang
        self.m_words_list = (_MoneroWordsListGetter.Instance().GetByLanguage(lang)
                             if lang is not None
                             else None)

    def Decode(self,
               mnemonic: Union[str, MoneroMnemonic]) -> bytes:
        """ Decode a mnemonic phrase to bytes (no checksum).

        Args:
            mnemonic (str or MoneroMnemonic object): MoneroMnemonic

        Returns:
            bytes: Decoded bytes

        Raises:
            MoneroChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        if isinstance(mnemonic, str):
            mnemonic = MoneroMnemonic.FromString(mnemonic)

        words = mnemonic.ToList()

        # Check mnemonic length
        if mnemonic.WordsCount() not in MoneroMnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list, lang = (_MoneroWordsListFinder.FindLanguage(mnemonic)
                            if self.m_words_list is None
                            else (self.m_words_list, self.lang))

        # Verify checksum if needed
        if mnemonic.WordsCount() in MoneroMnemonicConst.MNEMONIC_WORD_NUM_CHKSUM:
            chksum_word = _MoneroMnemonicUtils.ComputeChecksum(words[:-1], lang)
            if words[-1] != chksum_word:
                raise MoneroChecksumError(f"Invalid checksum (expected {chksum_word}, got {words[-1]})")

        # Consider 3 words at a time, 3 words represent 4 bytes
        entropy_bytes = b""
        n = MoneroMnemonicConst.WORDS_LIST_NUM

        for i in range(len(words) // 3):
            word1, word2, word3 = words[(i*3):(i*3) + 3]

            # Get back words indexes
            w1 = words_list.GetWordIdx(word1)
            w2 = words_list.GetWordIdx(word2) % n
            w3 = words_list.GetWordIdx(word3) % n

            # Get back bytes
            x = w1 + (n * ((w2 - w1) % n)) + (n * n * ((w3 - w2) % n))

            entropy_bytes += ConvUtils.IntegerToBytes(x, bytes_num=4, endianness="little")

        return entropy_bytes
