# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module for SLIP39 mnemonic utility classes."""

# Imports
import os
from typing import List, Tuple

from typing_extensions import override

from bip_utils.slip.slip39.slip39_mnemonic import Slip39Languages, Slip39MnemonicConst
from bip_utils.utils.mnemonic import MnemonicLanguages, MnemonicWordsList, MnemonicWordsListGetterBase


class Slip39WordsListGetter(MnemonicWordsListGetterBase):
    """
    SLIP39 words list getter class.
    It allows to get words list by language so that they are loaded from file only once per language.
    """

    @override
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
            TypeError: If the language is not a Slip39Languages enum
            ValueError: If loaded words list is not valid
        """
        if not isinstance(lang, Slip39Languages):
            raise TypeError("Language is not an enumerative of Slip39Languages")
        return self._LoadWordsList(lang,
                                   self.__GetLanguageFile(lang),
                                   Slip39MnemonicConst.WORDS_LIST_NUM)

    @staticmethod
    def __GetLanguageFile(lang: MnemonicLanguages) -> str:
        """
        Get the specified language file name.

        Args:
            lang (MnemonicLanguages): Language

        Returns:
            str: Language file name
        """
        return os.path.join(os.path.dirname(__file__),
                            Slip39MnemonicConst.LANGUAGE_FILES[lang])


class Slip39Rs1024Const:
    """Class container for SLIP39 RS1024 checksum constants."""

    # Generator coefficients
    GENERATOR: Tuple[int, ...] = (
        0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
        0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120,
    )


class Slip39Rs1024:
    """
    SLIP39 RS1024 checksum class.
    It computes and verifies the Reed-Solomon checksum over GF(1024) of the mnemonic word indexes.
    """

    @classmethod
    def Compute(cls,
                custom_str: str,
                data: List[int]) -> List[int]:
        """
        Compute the checksum.

        Args:
            custom_str (str) : Customization string
            data (list[int]) : Data word indexes

        Returns:
            list[int]: Checksum word indexes
        """
        checksum_words_num = Slip39MnemonicConst.CHECKSUM_WORDS_NUM
        polymod = cls.__Polymod(cls.__CustomStrToValues(custom_str) + data + [0] * checksum_words_num) ^ 1
        return Slip39MnemonicUtils.IntToWordIndexes(polymod, checksum_words_num)

    @classmethod
    def Verify(cls,
               custom_str: str,
               data: List[int]) -> bool:
        """
        Verify the checksum.

        Args:
            custom_str (str): Customization string
            data (list[int]): Word indexes, including the checksum ones

        Returns:
            bool: True if valid, false otherwise
        """
        return cls.__Polymod(cls.__CustomStrToValues(custom_str) + data) == 1

    @staticmethod
    def __CustomStrToValues(custom_str: str) -> List[int]:
        """
        Convert the customization string to a list of values.

        Args:
            custom_str (str): Customization string

        Returns:
            list[int]: Values
        """
        return [ord(c) for c in custom_str]

    @staticmethod
    def __Polymod(values: List[int]) -> int:
        """
        Compute the polymod.

        Args:
            values (list[int]): Values

        Returns:
            int: Computed polymod
        """
        chk = 1
        for value in values:
            top = chk >> 20
            chk = ((chk & 0xFFFFF) << 10) ^ value
            for i, gen in enumerate(Slip39Rs1024Const.GENERATOR):
                if (top >> i) & 1:
                    chk ^= gen
        return chk


class Slip39MnemonicUtils:
    """Class container for SLIP39 mnemonic utility functions."""

    @staticmethod
    def ChecksumCustomString(extendable: bool) -> str:
        """
        Get the checksum customization string.

        Args:
            extendable (bool): Extendable backup flag

        Returns:
            str: Customization string
        """
        return (Slip39MnemonicConst.CHECKSUM_CUSTOM_STR_EXT
                if extendable
                else Slip39MnemonicConst.CHECKSUM_CUSTOM_STR)

    @staticmethod
    def IntToWordIndexes(value: int,
                         words_num: int) -> List[int]:
        """
        Convert an integer to word indexes (10-bit, big endian).

        Args:
            value (int)    : Value
            words_num (int): Number of words

        Returns:
            list[int]: Word indexes
        """
        word_mask = Slip39MnemonicConst.WORDS_LIST_NUM - 1
        return [
            (value >> (Slip39MnemonicConst.WORD_BIT_LEN * (words_num - 1 - i))) & word_mask
            for i in range(words_num)
        ]

    @staticmethod
    def WordIndexesToInt(word_indexes: List[int]) -> int:
        """
        Convert word indexes (10-bit, big endian) to an integer.

        Args:
            word_indexes (list[int]): Word indexes

        Returns:
            int: Value
        """
        value = 0
        for word_idx in word_indexes:
            value = (value << Slip39MnemonicConst.WORD_BIT_LEN) | word_idx
        return value

    @staticmethod
    def ValueWordsNum(value_byte_len: int) -> int:
        """
        Get the number of words needed to encode a share value (including padding).

        Args:
            value_byte_len (int): Share value length in bytes

        Returns:
            int: Number of words
        """
        return -(-(value_byte_len * 8) // Slip39MnemonicConst.WORD_BIT_LEN)
