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

"""Module for Electrum mnemonic."""

# Imports
from enum import auto, Enum, IntEnum, unique
from typing import Dict, List
from bip_utils.bip.bip39 import Bip39Languages, Bip39Mnemonic
from bip_utils.bip.bip39.bip39_mnemonic import Bip39MnemonicConst
from bip_utils.utils.mnemonic import MnemonicLanguages


@unique
class ElectrumWordsNum(IntEnum):
    """Enumerative for Electrum words number."""

    WORDS_NUM_12 = 12


@unique
class ElectrumLanguages(MnemonicLanguages):
    """Enumerative for Electrum languages."""

    CHINESE_SIMPLIFIED = Bip39Languages.CHINESE_SIMPLIFIED
    ENGLISH = Bip39Languages.ENGLISH
    PORTUGUESE = Bip39Languages.PORTUGUESE
    SPANISH = Bip39Languages.SPANISH


@unique
class ElectrumMnemonicTypes(Enum):
    """Enumerative for Electrum mnemonic types."""
    STANDARD = auto()       # Standard wallet
    SEGWIT = auto()         # Segwit wallet


class ElectrumMnemonicConst:
    """Class container for Electrum mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[ElectrumWordsNum] = [
        ElectrumWordsNum.WORDS_NUM_12,
    ]

    # Mnemonic types to prefix
    TYPE_TO_PREFIX: Dict[ElectrumMnemonicTypes, str] = {
        ElectrumMnemonicTypes.STANDARD: "01",
        ElectrumMnemonicTypes.SEGWIT: "100",
    }

    # Word length in bit
    WORD_BIT_LEN: int = Bip39MnemonicConst.WORD_BIT_LEN


class ElectrumMnemonic(Bip39Mnemonic):
    """Electrum mnemonic class."""
