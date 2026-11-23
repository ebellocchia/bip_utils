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

"""
Module for SLIP39 mnemonic.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from enum import IntEnum, auto, unique
from typing import Dict, List, Union

from typing_extensions import override

from bip_utils.utils.mnemonic import Mnemonic, MnemonicLanguages


@unique
class Slip39WordsNum(IntEnum):
    """Enumerative for SLIP39 words number (for 128-bit and 256-bit master secrets)."""

    WORDS_NUM_20 = 20
    WORDS_NUM_33 = 33


@unique
class Slip39Languages(MnemonicLanguages):
    """Enumerative for SLIP39 languages (SLIP39 only defines the English words list)."""

    ENGLISH = auto()


class Slip39MnemonicConst:
    """Class container for SLIP39 mnemonic constants."""

    # Accepted mnemonic word numbers for random master secrets
    MNEMONIC_WORD_NUM: List[Slip39WordsNum] = [
        Slip39WordsNum.WORDS_NUM_20,
        Slip39WordsNum.WORDS_NUM_33,
    ]
    # Master secret length in bytes for each words number
    WORDS_NUM_TO_SECRET_BYTE_LEN: Dict[Slip39WordsNum, int] = {
        Slip39WordsNum.WORDS_NUM_20: 16,
        Slip39WordsNum.WORDS_NUM_33: 32,
    }

    # Language files
    LANGUAGE_FILES: Dict[MnemonicLanguages, str] = {
        Slip39Languages.ENGLISH: "wordlist/english.txt",
    }

    # Total number of words
    WORDS_LIST_NUM: int = 1024
    # Word length in bit
    WORD_BIT_LEN: int = 10

    # Field lengths in bit
    ID_BIT_LEN: int = 15
    ITER_EXP_BIT_LEN: int = 4
    PARAM_BIT_LEN: int = 4
    # Field lengths in words
    ID_EXT_ITER_EXP_WORDS_NUM: int = 2
    SHARE_PARAMS_WORDS_NUM: int = 2
    CHECKSUM_WORDS_NUM: int = 3
    METADATA_WORDS_NUM: int = ID_EXT_ITER_EXP_WORDS_NUM + SHARE_PARAMS_WORDS_NUM + CHECKSUM_WORDS_NUM

    # Maximum number of groups and of members in a group
    MAX_SHARES_NUM: int = 16
    # Minimum master secret length in bytes
    MIN_SECRET_BYTE_LEN: int = 16
    # Minimum number of words (128-bit master secret)
    MIN_WORDS_NUM: int = 20
    # Maximum padding of the share value in bit
    MAX_PADDING_BIT_LEN: int = 8

    # Checksum customization strings
    CHECKSUM_CUSTOM_STR: str = "shamir"
    CHECKSUM_CUSTOM_STR_EXT: str = "shamir_extendable"


class Slip39Mnemonic(Mnemonic):
    """
    SLIP39 mnemonic class.
    It represents a single share and adds lower case normalization to mnemonic.
    """

    @override
    @staticmethod
    def _Normalize(mnemonic: Union[str, List[str]]) -> List[str]:
        """
        Normalize mnemonic list.

        Args:
            mnemonic (str or list[str]): Mnemonic

        Returns:
            list[str]: Normalized mnemonic list
        """
        mnemonic = Mnemonic._Normalize(mnemonic)
        return [s.lower() for s in mnemonic]
