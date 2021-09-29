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
from typing import Dict, List, Optional, Union
from bip_utils.bip39.bip39_ex import Bip39ChecksumError
from bip_utils.bip39.bip39_entropy_generator import Bip39EntropyGenerator
from bip_utils.utils import AlgoUtils, ConvUtils, CryptoUtils


@unique
class Bip39WordsNum(IntEnum):
    """ Enumerative for BIP-0039 words number. """

    WORDS_NUM_12 = 12,
    WORDS_NUM_15 = 15,
    WORDS_NUM_18 = 18,
    WORDS_NUM_21 = 21,
    WORDS_NUM_24 = 24,


@unique
class Bip39Languages(Enum):
    """ Enumerative for BIP-0039 languages. """

    CHINESE_SIMPLIFIED = auto(),
    CHINESE_TRADITIONAL = auto(),
    CZECH = auto(),
    ENGLISH = auto(),
    FRENCH = auto(),
    ITALIAN = auto(),
    KOREAN = auto(),
    PORTUGUESE = auto(),
    SPANISH = auto(),


class Bip39MnemonicConst:
    """ Class container for BIP39 constants. """

    # Accepted mnemonic word lengths
    MNEMONIC_WORD_LEN: List[Bip39WordsNum] = [
        Bip39WordsNum.WORDS_NUM_12,
        Bip39WordsNum.WORDS_NUM_15,
        Bip39WordsNum.WORDS_NUM_18,
        Bip39WordsNum.WORDS_NUM_21,
        Bip39WordsNum.WORDS_NUM_24,
    ]

    # Language files
    LANGUAGE_FILES: Dict[Bip39Languages, str] = {
        Bip39Languages.ENGLISH: "bip39_words/english.txt",
        Bip39Languages.ITALIAN: "bip39_words/italian.txt",
        Bip39Languages.FRENCH: "bip39_words/french.txt",
        Bip39Languages.SPANISH: "bip39_words/spanish.txt",
        Bip39Languages.PORTUGUESE: "bip39_words/portuguese.txt",
        Bip39Languages.CZECH: "bip39_words/czech.txt",
        Bip39Languages.CHINESE_SIMPLIFIED: "bip39_words/chinese_simplified.txt",
        Bip39Languages.CHINESE_TRADITIONAL: "bip39_words/chinese_traditional.txt",
        Bip39Languages.KOREAN: "bip39_words/korean.txt",
    }

    # Languages supporting binary search
    LANGUAGE_BIN_SEARCH: List[Bip39Languages] = [
        Bip39Languages.ENGLISH,
        Bip39Languages.ITALIAN,
        Bip39Languages.PORTUGUESE,
        Bip39Languages.CZECH
    ]

    # Total number of words
    WORDS_LIST_NUM: int = 2048
    # Word length in bit
    WORD_BIT_LEN: int = 11


class Bip39Mnemonic:
    """ BIP39 mnemonic class. It represents a generic mnemonic phrase.
    It acts as a simple container with some helper functions, so it doesn't validate the given mnemonic.
    """

    @classmethod
    def FromString(cls,
                   mnemonic_str: str) -> Bip39Mnemonic:
        """ Create a class from mnemonic string.

        Args:
            mnemonic_str (str): Mnemonic string

        Returns:
            Bip39Mnemonic: Mnemonic object
        """
        return cls.FromList(mnemonic_str.split(" "))

    @classmethod
    def FromList(cls,
                 mnemonic_list: List[str]) -> Bip39Mnemonic:
        """ Create a class from mnemonic list.

        Args:
            mnemonic_list (list): Mnemonic list

        Returns:
            Bip39Mnemonic: Mnemonic object
        """
        return cls(mnemonic_list)

    def __init__(self,
                 mnemonic_list: List[str]) -> None:
        """ Construct class.

        Args:
            mnemonic_list (list): Mnemonic list
        """
        self.m_mnemonic_list = self.__NormalizeNfkd(mnemonic_list)

    def WordsCount(self) -> int:
        """ Get the words count.

        Returns:
            int: Words count
        """
        return len(self.m_mnemonic_list)

    def ToList(self) -> List[str]:
        """ Get the mnemonic as a list.

        Returns:
            list: Mnemonic as a list
        """
        return self.m_mnemonic_list

    def ToStr(self) -> str:
        """ Get the mnemonic as a string.

        Returns:
            str: Mnemonic as a string
        """
        return " ".join(self.m_mnemonic_list)

    def __str__(self) -> str:
        """ Get the mnemonic as a string.

        Returns:
            str: Mnemonic as a string
        """
        return self.ToStr()

    @staticmethod
    def __NormalizeNfkd(mnemonic_list: List[str]) -> List[str]:
        """ Normalize mnemonic list using NFKD.

        Args:
            mnemonic_list (list): Mnemonic list

        Returns:
            list: Normalized mnemonic list
        """
        return list(map(lambda s: ConvUtils.NormalizeNfkd(s), mnemonic_list))


class _Bip39WordsList:
    """ BIP39 words list class. """

    def __init__(self,
                 words_list: List[str],
                 lang: Bip39Languages) -> None:
        """ Construct class by reading the words list from file.

        Args:
            lang (Bip39Languages): Language

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, Bip39Languages):
            raise TypeError("Language is not an enumerative of Bip39Languages")
        if len(words_list) != Bip39MnemonicConst.WORDS_LIST_NUM:
            raise ValueError(f"Number of words list ({len(words_list)}) is not valid")

        self.m_lang = lang
        self.m_words_list = words_list

    def Language(self) -> Bip39Languages:
        """ Get words list language.

        Returns:
            Bip39Languages: Language
        """
        return self.m_lang

    def GetWordIdx(self,
                   word: str) -> int:
        """ Get the index of the specified word, by searching it in the list.

        Args:
            word (str): Word to be searched

        Returns:
            int: Word index

        Raises:
            ValueError: If the word is not found
        """

        # Use binary search when possible
        if self.m_lang in Bip39MnemonicConst.LANGUAGE_BIN_SEARCH:
            idx = AlgoUtils.BinarySearch(self.m_words_list, word)
            if idx == -1:
                raise ValueError(f"Word '{word}' is not existent in word list")
        else:
            idx = self.m_words_list.index(word)

        return idx

    def GetWordAtIdx(self,
                     word_idx: int) -> str:
        """ Get the word at the specified index.

        Args:
            word_idx (int): Word index

        Returns:
            str: Word at the specified index
        """
        return self.m_words_list[word_idx]


class _Bip39WordsListFileReader:
    """ BIP39 words list file reader class. It reads the words list from a file. """

    @staticmethod
    def LoadFile(lang: Bip39Languages) -> _Bip39WordsList:
        """ Load words list file correspondent to the specified language.

        Args:
            lang (Bip39Languages): Language

        Returns:
            _Bip39WordsList: _Bip39WordsList object

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, Bip39Languages):
            raise TypeError("Language is not an enumerative of Bip39Languages")

        # Get file path
        file_name = Bip39MnemonicConst.LANGUAGE_FILES[lang]
        file_path = os.path.join(os.path.dirname(__file__), file_name)
        # Read file
        with open(file_path, "r", encoding="utf-8") as fin:
            words_list = [word.strip() for word in fin.readlines() if word.strip() != ""]

        return _Bip39WordsList(words_list, lang)


class _Bip39WordsListGetter:
    """ BIP39 words list getter class. It allows to get words list by language so that
    they are loaded from file only once per language (i.e. on the first request).
    """

    # Global instance
    __instance = None

    def __init__(self):
        """ Construct class. """
        self.m_words_lists = {}

    def GetByLanguage(self,
                      lang: Bip39Languages) -> _Bip39WordsList:
        """ Get words list by language.
        Words list of a specific language are loaded from file only the first time they are requested.

        Args:
            lang (Bip39Languages): Language

        Returns:
            _Bip39WordsList object: _Bip39WordsList object

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """

        # Only load words list for a specific language the first time it is requested
        try:
            return self.m_words_lists[lang]
        except KeyError:
            self.m_words_lists[lang] = _Bip39WordsListFileReader.LoadFile(lang)
            return self.m_words_lists[lang]

    @classmethod
    def Instance(cls) -> _Bip39WordsListGetter:
        """ Get the global class instance.

        Returns:
            _Bip39WordsListGetter object: _Bip39WordsListGetter object
        """
        if cls.__instance is None:
            cls.__instance = _Bip39WordsListGetter()
        return cls.__instance


class _Bip39WordsListFinder:
    """ BIP39 words list finder class.
    It automatically finds the correct words list from a mnemonic.
    """

    @staticmethod
    def FindLanguage(mnemonic: Bip39Mnemonic) -> _Bip39WordsList:
        """ Automatically find the language of the specified mnemonic and
        get the correct _Bip39WordsList class for it.

        Args:
            mnemonic (Bip39Mnemonic object): Mnemonic object

        Returns:
           _Bip39WordsList object: _Bip39WordsList object

        Raises:
            ValueError: If the mnemonic language cannot be found
        """

        for lang in Bip39Languages:
            # Search all the words because some languages have words in common
            # (e.g. 'fatigue' both in English and French)
            # It's more time consuming, but considering only the first word can detect the wrong language sometimes
            try:
                words_list = _Bip39WordsListGetter.Instance().GetByLanguage(lang)
                for word in mnemonic.ToList():
                    words_list.GetWordIdx(word)
                return words_list
            except ValueError:
                continue

        # Language not found
        raise ValueError(f"Invalid language for mnemonic '{mnemonic.ToStr()}'")


class Bip39MnemonicEncoder:
    """ BIP39 mnemonic encoder class. It encodes bytes to the mnemonic phrase. """

    def __init__(self,
                 lang: Bip39Languages) -> None:
        """ Construct class.

        Args:
            lang (Bip39Languages): Language

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        self.m_words_list = _Bip39WordsListGetter.Instance().GetByLanguage(lang)

    def Encode(self,
               entropy_bytes: bytes) -> Bip39Mnemonic:
        """ Encode bytes to mnemonic phrase.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 160, 192, 224, 256)

        Returns:
            Bip39Mnemonic object: Encoded mnemonic

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not Bip39EntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Convert entropy to binary string
        entropy_bin_str = ConvUtils.BytesToBinaryStr(entropy_bytes, entropy_byte_len * 8)
        # Get entropy hash as binary string
        entropy_hash_bin_str = ConvUtils.BytesToBinaryStr(CryptoUtils.Sha256(entropy_bytes),
                                                          CryptoUtils.Sha256DigestSize() * 8)
        # Get mnemonic binary string by concatenating entropy and checksum
        mnemonic_bin_str = entropy_bin_str + entropy_hash_bin_str[:entropy_byte_len // 4]

        # Get mnemonic from entropy
        mnemonic = []
        for i in range(len(mnemonic_bin_str) // Bip39MnemonicConst.WORD_BIT_LEN):
            # Get current word index
            word_bin_str = mnemonic_bin_str[i * Bip39MnemonicConst.WORD_BIT_LEN:(i + 1) * Bip39MnemonicConst.WORD_BIT_LEN]
            word_idx = ConvUtils.BinaryStrToInteger(word_bin_str)
            # Get word at given index
            mnemonic.append(self.m_words_list.GetWordAtIdx(word_idx))

        return Bip39Mnemonic.FromList(mnemonic)


class Bip39MnemonicDecoder:
    """ BIP39 mnemonic decoder class. It decodes a mnemonic phrase to bytes. """

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[Bip39Languages] = None) -> None:
        """ Construct class.

        Args:
            lang (Bip39Languages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        self.m_words_list = (_Bip39WordsListGetter.Instance().GetByLanguage(lang)
                             if lang is not None
                             else None)

    def Decode(self,
               mnemonic: Union[str, Bip39Mnemonic]) -> bytes:
        """ Decode a mnemonic phrase to bytes (no checksum).

        Args:
            mnemonic (str or Bip39Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes (no checksum)

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_bin_str = self.__DecodeAndVerifyBinaryStr(mnemonic)

        return self.__EntropyBytesFromBinaryStr(mnemonic_bin_str)

    def DecodeWithChecksum(self,
                           mnemonic: Union[str, Bip39Mnemonic]) -> bytes:
        """ Decode a mnemonic phrase to bytes (with checksum).

        Args:
            mnemonic (str or Bip39Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes (with checksum)

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_bin_str = self.__DecodeAndVerifyBinaryStr(mnemonic)

        # Compute pad bit length
        mnemonic_bit_len = len(mnemonic_bin_str)
        pad_bit_len = (mnemonic_bit_len
                       if mnemonic_bit_len % 8 == 0
                       else mnemonic_bit_len + (8 - mnemonic_bit_len % 8))

        return ConvUtils.BinaryStrToBytes(mnemonic_bin_str, pad_bit_len // 4)

    def __DecodeAndVerifyBinaryStr(self,
                                   mnemonic: Union[str, Bip39Mnemonic]) -> str:
        """ Decode a mnemonic phrase to its mnemonic binary string by verifying the checksum.

        Args:
            mnemonic (str or Bip39Mnemonic object): Mnemonic

        Returns:
            str: Mnemonic binary string

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        if isinstance(mnemonic, str):
            mnemonic = Bip39Mnemonic.FromString(mnemonic)

        # Check mnemonic length
        if mnemonic.WordsCount() not in Bip39MnemonicConst.MNEMONIC_WORD_LEN:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list = (_Bip39WordsListFinder.FindLanguage(mnemonic)
                      if self.m_words_list is None
                      else self.m_words_list)

        # Get back mnemonic binary string
        mnemonic_bin_str = self.__MnemonicToBinaryStr(mnemonic, words_list)

        # Verify checksum
        checksum_bin_str = mnemonic_bin_str[-self.__GetChecksumLen(mnemonic_bin_str):]
        comp_checksum_bin_str = self.__ComputeChecksumBinaryStr(mnemonic_bin_str)

        if checksum_bin_str != comp_checksum_bin_str:
            raise Bip39ChecksumError(
                f"Invalid checksum (expected {checksum_bin_str}, got {comp_checksum_bin_str})"
            )

        return mnemonic_bin_str

    def __ComputeChecksumBinaryStr(self,
                                   mnemonic_bin_str: str) -> str:
        """ Compute checksum from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           str: Computed checksum binary string
        """

        # Get entropy bytes
        entropy_bytes = self.__EntropyBytesFromBinaryStr(mnemonic_bin_str)
        # Convert entropy hash to binary string
        entropy_hash_bin_str = ConvUtils.BytesToBinaryStr(CryptoUtils.Sha256(entropy_bytes),
                                                          CryptoUtils.Sha256DigestSize() * 8)

        # Return checksum
        return entropy_hash_bin_str[:self.__GetChecksumLen(mnemonic_bin_str)]

    def __EntropyBytesFromBinaryStr(self,
                                    mnemonic_bin_str: str) -> bytes:
        """ Get entropy bytes from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           bytes: Entropy bytes
        """

        # Get checksum length
        checksum_len = self.__GetChecksumLen(mnemonic_bin_str)
        # Get back entropy binary string
        entropy_bin_str = mnemonic_bin_str[:-checksum_len]

        # Get entropy bytes from binary string
        return ConvUtils.BinaryStrToBytes(entropy_bin_str, checksum_len * 8)

    @staticmethod
    def __MnemonicToBinaryStr(mnemonic: Bip39Mnemonic,
                              words_list: _Bip39WordsList) -> str:
        """ Get mnemonic binary string from mnemonic phrase.

        Args:
            mnemonic (Bip39Mnemonic object)    : Mnemonic object
            words_list (_Bip39WordsList object): Words list object

        Returns:
           str: Mnemonic binary string

        Raises:
            ValueError: If the one of the mnemonic word is not valid
        """

        # Convert each word to its index in binary format
        mnemonic_bin_str = map(lambda word: ConvUtils.IntegerToBinaryStr(words_list.GetWordIdx(word),
                                                                         Bip39MnemonicConst.WORD_BIT_LEN),
                               mnemonic.ToList())

        return "".join(mnemonic_bin_str)

    @staticmethod
    def __GetChecksumLen(mnemonic_bin_str: str) -> int:
        """ Get checksum length from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           int: Checksum length
        """
        return len(mnemonic_bin_str) // 33
