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

"""Module for Electrum v2 mnemonic."""

# Imports
from enum import Enum, IntEnum, auto, unique
from typing import Dict, List

from bip_utils.bip.bip39 import Bip39Languages, Bip39Mnemonic
from bip_utils.bip.bip39.bip39_mnemonic import Bip39MnemonicConst
from bip_utils.utils.mnemonic import MnemonicLanguages


@unique
class ElectrumV2WordsNum(IntEnum):
    """Enumerative for Electrum words number (v2)."""

    WORDS_NUM_12 = 12
    WORDS_NUM_24 = 24


@unique
class ElectrumV2Languages(MnemonicLanguages):
    """Enumerative for Electrum languages (v2)."""

    CHINESE_SIMPLIFIED = Bip39Languages.CHINESE_SIMPLIFIED
    ENGLISH = Bip39Languages.ENGLISH
    PORTUGUESE = Bip39Languages.PORTUGUESE
    SPANISH = Bip39Languages.SPANISH


@unique
class ElectrumV2MnemonicTypes(Enum):
    """Enumerative for Electrum v2 mnemonic types."""

    STANDARD = auto()       # Standard wallet
    SEGWIT = auto()         # Segwit wallet
    STANDARD_2FA = auto()   # Standard 2FA wallet
    SEGWIT_2FA = auto()     # Segwit 2FA wallet


class ElectrumV2MnemonicConst:
    """Class container for Electrum v2 mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[ElectrumV2WordsNum] = [
        ElectrumV2WordsNum.WORDS_NUM_12,
        ElectrumV2WordsNum.WORDS_NUM_24,
    ]

    # Mnemonic types to prefix
    TYPE_TO_PREFIX: Dict[ElectrumV2MnemonicTypes, str] = {
        ElectrumV2MnemonicTypes.STANDARD: "01",
        ElectrumV2MnemonicTypes.SEGWIT: "100",
        ElectrumV2MnemonicTypes.STANDARD_2FA: "101",
        ElectrumV2MnemonicTypes.SEGWIT_2FA: "102",
    }

    # Word length in bit
    WORD_BIT_LEN: int = Bip39MnemonicConst.WORD_BIT_LEN


class ElectrumV2Mnemonic(Bip39Mnemonic):
    """Electrum mnemonic class."""
