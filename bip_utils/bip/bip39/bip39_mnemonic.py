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

"""Module for BIP39 mnemonic."""

# Imports
from enum import auto, IntEnum, unique
from typing import Dict, List
from bip_utils.utils.misc import StringUtils
from bip_utils.utils.mnemonic import Mnemonic, MnemonicLanguages


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
    """Class container for BIP39 mnemonic constants."""

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
            mnemonic_list (list[str]): Mnemonic list
        """

        # Normalize using NFKD as specified by BIP-0039
        super().__init__(self.__NormalizeNfkd(mnemonic_list))

    @staticmethod
    def __NormalizeNfkd(mnemonic_list: List[str]) -> List[str]:
        """
        Normalize mnemonic list using NFKD.

        Args:
            mnemonic_list (list[str]): Mnemonic list

        Returns:
            list[str]: Normalized mnemonic list
        """
        return list(map(StringUtils.NormalizeNfkd, mnemonic_list))
