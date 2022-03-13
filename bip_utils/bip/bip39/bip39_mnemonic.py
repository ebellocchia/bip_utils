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
Module for BIP39 mnemonic decoding/encoding.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki.
"""

# Imports
import os
from enum import auto, IntEnum, unique
from typing import Dict, List, Optional, Union
from bip_utils.bip.bip39.bip39_ex import Bip39ChecksumError
from bip_utils.bip.bip39.bip39_entropy_generator import Bip39EntropyGenerator
from bip_utils.utils.misc import BytesUtils, CryptoUtils, IntegerUtils, StringUtils
from bip_utils.utils.mnemonic import (
    Mnemonic, MnemonicLanguages, MnemonicWordsList, MnemonicWordsListGetterBase
)


@unique
class Bip39WordsNum(IntEnum):
    """Enumerative for BIP39 words number."""

    WORDS_NUM_12 = 12
    WORDS_NUM_15 = 15
    WORDS_NUM_18 = 18
    WORDS_NUM_21 = 21
    WORDS_NUM_24 = 24


@unique
class Bip39Languages(MnemonicLanguages):
    """Enumerative for BIP39 languages."""

    CHINESE_SIMPLIFIED = auto()
    CHINESE_TRADITIONAL = auto()
    CZECH = auto()
    ENGLISH = auto()
    FRENCH = auto()
    ITALIAN = auto()
    KOREAN = auto()
    PORTUGUESE = auto()
    SPANISH = auto()


class Bip39MnemonicConst:
    """Class container for BIP39 constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[Bip39WordsNum] = [
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

    # Total number of words
    WORDS_LIST_NUM: int = 2048
    # Word length in bit
    WORD_BIT_LEN: int = 11


class Bip39Mnemonic(Mnemonic):
    """
    BIP39 mnemonic class.
    It adds NFKD normalization to mnemonic.
    """

    def __init__(self,
                 mnemonic_list: List[str]) -> None:
        """
        Construct class.

        Args:
            mnemonic_list (list): Mnemonic list
        """

        # Normalize using NFKD as specified by BIP-0039
        super().__init__(self.__NormalizeNfkd(mnemonic_list))

    @staticmethod
    def __NormalizeNfkd(mnemonic_list: List[str]) -> List[str]:
        """
        Normalize mnemonic list using NFKD.

        Args:
            mnemonic_list (list): Mnemonic list

        Returns:
            list: Normalized mnemonic list
        """
        return list(map(StringUtils.NormalizeNfkd, mnemonic_list))


class _Bip39WordsListGetter(MnemonicWordsListGetterBase):
    """
    BIP39 words list getter class.
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
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, Bip39Languages):
            raise TypeError("Language is not an enumerative of Bip39Languages")

        # Only load words list for a specific language the first time it is requested
        try:
            return self.m_words_lists[lang]
        except KeyError:
            self.m_words_lists[lang] = self._LoadWordsList(self.__GetLanguageFile(lang),
                                                           Bip39MnemonicConst.WORDS_LIST_NUM)

            return self.m_words_lists[lang]

    @staticmethod
    def __GetLanguageFile(lang: Bip39Languages) -> str:
        """
        Get the specified language file name.

        Args:
            lang (Bip39Languages): Language

        Returns:
            str: Language file name
        """
        return os.path.join(os.path.dirname(__file__),
                            Bip39MnemonicConst.LANGUAGE_FILES[lang])


class _Bip39WordsListFinder:
    """
    BIP39 words list finder class.
    It automatically finds the correct words list from a mnemonic.
    """

    @staticmethod
    def FindLanguage(mnemonic: Mnemonic) -> MnemonicWordsList:
        """
        Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.

        Args:
            mnemonic (Mnemonic object): Mnemonic object

        Returns:
           MnemonicWordsList object: MnemonicWordsList object

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
    """
    BIP39 mnemonic encoder class.
    It encodes bytes to the mnemonic phrase.
    """

    m_words_list: MnemonicWordsList

    def __init__(self,
                 lang: Bip39Languages) -> None:
        """
        Construct class.

        Args:
            lang (Bip39Languages): Language

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If loaded words list is not valid
        """
        self.m_words_list = _Bip39WordsListGetter.Instance().GetByLanguage(lang)

    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode bytes to mnemonic phrase.

        Args:
            entropy_bytes (bytes): Entropy bytes (accepted lengths in bits: 128, 160, 192, 224, 256)

        Returns:
            Mnemonic object: Encoded mnemonic

        Raises:
            ValueError: If bytes length is not valid
        """

        # Check entropy length
        entropy_byte_len = len(entropy_bytes)
        if not Bip39EntropyGenerator.IsValidEntropyByteLen(entropy_byte_len):
            raise ValueError(f"Entropy byte length ({entropy_byte_len}) is not valid")

        # Convert entropy to binary string
        entropy_bin_str = BytesUtils.ToBinaryStr(entropy_bytes, entropy_byte_len * 8)
        # Get entropy hash as binary string
        entropy_hash_bin_str = BytesUtils.ToBinaryStr(CryptoUtils.Sha256(entropy_bytes),
                                                      CryptoUtils.Sha256DigestSize() * 8)
        # Get mnemonic binary string by concatenating entropy and checksum
        mnemonic_bin_str = entropy_bin_str + entropy_hash_bin_str[:entropy_byte_len // 4]

        # Get mnemonic from entropy
        mnemonic = []
        for i in range(len(mnemonic_bin_str) // Bip39MnemonicConst.WORD_BIT_LEN):
            # Get current word index
            word_bin_str = (mnemonic_bin_str[i * Bip39MnemonicConst.WORD_BIT_LEN:(i + 1)
                            * Bip39MnemonicConst.WORD_BIT_LEN])
            word_idx = IntegerUtils.FromBinaryStr(word_bin_str)
            # Get word at given index
            mnemonic.append(self.m_words_list.GetWordAtIdx(word_idx))

        return Bip39Mnemonic.FromList(mnemonic)


class Bip39MnemonicDecoder:
    """
    BIP39 mnemonic decoder class.
    It decodes a mnemonic phrase to bytes.
    """

    m_words_list: Optional[MnemonicWordsList]

    #
    # Public methods
    #

    def __init__(self,
                 lang: Optional[Bip39Languages] = None) -> None:
        """
        Construct class.

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
               mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to bytes (no checksum).

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            bytes: Decoded bytes (no checksum)

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_bin_str = self.__DecodeAndVerifyBinaryStr(mnemonic)

        return self.__EntropyBytesFromBinaryStr(mnemonic_bin_str)

    def DecodeWithChecksum(self,
                           mnemonic: Union[str, Mnemonic]) -> bytes:
        """
        Decode a mnemonic phrase to bytes (with checksum).

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

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

        return BytesUtils.FromBinaryStr(mnemonic_bin_str, pad_bit_len // 4)

    def __DecodeAndVerifyBinaryStr(self,
                                   mnemonic: Union[str, Mnemonic]) -> str:
        """
        Decode a mnemonic phrase to its mnemonic binary string by verifying the checksum.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic

        Returns:
            str: Mnemonic binary string

        Raises:
            Bip39ChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        mnemonic_obj = Bip39Mnemonic.FromString(mnemonic) if isinstance(mnemonic, str) else mnemonic

        # Check mnemonic length
        if mnemonic_obj.WordsCount() not in Bip39MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Mnemonic words count is not valid ({mnemonic_obj.WordsCount()})")

        # Detect language if it was not specified at construction
        words_list = (_Bip39WordsListFinder.FindLanguage(mnemonic_obj)
                      if self.m_words_list is None
                      else self.m_words_list)

        # Get back mnemonic binary string
        mnemonic_bin_str = self.__MnemonicToBinaryStr(mnemonic_obj, words_list)

        # Verify checksum
        checksum_bin_str = mnemonic_bin_str[-self.__GetChecksumLen(mnemonic_bin_str):]
        checksum_bin_str_got = self.__ComputeChecksumBinaryStr(mnemonic_bin_str)

        if checksum_bin_str != checksum_bin_str_got:
            raise Bip39ChecksumError(
                f"Invalid checksum (expected {checksum_bin_str}, got {checksum_bin_str_got})"
            )

        return mnemonic_bin_str

    def __ComputeChecksumBinaryStr(self,
                                   mnemonic_bin_str: str) -> str:
        """
        Compute checksum from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           str: Computed checksum binary string
        """

        # Get entropy bytes
        entropy_bytes = self.__EntropyBytesFromBinaryStr(mnemonic_bin_str)
        # Convert entropy hash to binary string
        entropy_hash_bin_str = BytesUtils.ToBinaryStr(CryptoUtils.Sha256(entropy_bytes),
                                                      CryptoUtils.Sha256DigestSize() * 8)

        # Return checksum
        return entropy_hash_bin_str[:self.__GetChecksumLen(mnemonic_bin_str)]

    def __EntropyBytesFromBinaryStr(self,
                                    mnemonic_bin_str: str) -> bytes:
        """
        Get entropy bytes from mnemonic binary string.

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
        return BytesUtils.FromBinaryStr(entropy_bin_str, checksum_len * 8)

    @staticmethod
    def __MnemonicToBinaryStr(mnemonic: Mnemonic,
                              words_list: MnemonicWordsList) -> str:
        """
        Get mnemonic binary string from mnemonic phrase.

        Args:
            mnemonic (Mnemonic object)           : Mnemonic object
            words_list (MnemonicWordsList object): Words list object

        Returns:
           str: Mnemonic binary string

        Raises:
            ValueError: If the one of the mnemonic word is not valid
        """

        # Convert each word to its index in binary format
        mnemonic_bin_str = map(lambda word: IntegerUtils.ToBinaryStr(words_list.GetWordIdx(word),
                                                                     Bip39MnemonicConst.WORD_BIT_LEN),
                               mnemonic.ToList())

        return "".join(mnemonic_bin_str)

    @staticmethod
    def __GetChecksumLen(mnemonic_bin_str: str) -> int:
        """
        Get checksum length from mnemonic binary string.

        Args:
            mnemonic_bin_str (str): Mnemonic binary string

        Returns:
           int: Checksum length
        """
        return len(mnemonic_bin_str) // 33
