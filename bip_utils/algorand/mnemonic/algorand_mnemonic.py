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

"""Module for Algorand mnemonic."""

# Imports
from enum import IntEnum, unique
from typing import List

from bip_utils.bip.bip39 import Bip39Languages, Bip39Mnemonic
from bip_utils.utils.mnemonic import MnemonicLanguages


@unique
class AlgorandWordsNum(IntEnum):
    """Enumerative for Algorand words number."""

    WORDS_NUM_25 = 25


@unique
class AlgorandLanguages(MnemonicLanguages):
    """Enumerative for Algorand languages."""

    ENGLISH = Bip39Languages.ENGLISH


class AlgorandMnemonicConst:
    """Class container for Algorand mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[AlgorandWordsNum] = [
        AlgorandWordsNum.WORDS_NUM_25,
    ]

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 2


class AlgorandMnemonic(Bip39Mnemonic):
    """Algorand mnemonic class."""
