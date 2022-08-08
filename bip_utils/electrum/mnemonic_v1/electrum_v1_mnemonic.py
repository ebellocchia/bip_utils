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

"""Module for Electrum v1 mnemonic."""

# Imports
from enum import IntEnum, auto, unique
from typing import Dict, List

from bip_utils.bip.bip39 import Bip39Mnemonic
from bip_utils.utils.mnemonic import MnemonicLanguages


@unique
class ElectrumV1WordsNum(IntEnum):
    """Enumerative for Electrum words number (v1)."""

    WORDS_NUM_12 = 12


@unique
class ElectrumV1Languages(MnemonicLanguages):
    """Enumerative for Electrum languages (v1)."""

    ENGLISH = auto()


class ElectrumV1MnemonicConst:
    """Class container for Electrum v1 mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[ElectrumV1WordsNum] = [
        ElectrumV1WordsNum.WORDS_NUM_12,
    ]

    # Language files
    LANGUAGE_FILES: Dict[MnemonicLanguages, str] = {
        ElectrumV1Languages.ENGLISH: "wordlist/english.txt",
    }

    # Total number of words
    WORDS_LIST_NUM: int = 1626


class ElectrumV1Mnemonic(Bip39Mnemonic):
    """Electrum v1 mnemonic class."""
