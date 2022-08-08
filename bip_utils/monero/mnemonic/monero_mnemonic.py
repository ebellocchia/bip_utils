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

"""Module for Monero mnemonic."""

# Imports
from enum import IntEnum, auto, unique
from typing import Dict, List

from bip_utils.utils.mnemonic import Mnemonic, MnemonicLanguages


@unique
class MoneroWordsNum(IntEnum):
    """Enumerative for Monero words number."""

    WORDS_NUM_12 = 12   # No checksum
    WORDS_NUM_13 = 13   # With checksum
    WORDS_NUM_24 = 24   # No checksum
    WORDS_NUM_25 = 25   # With checksum


@unique
class MoneroLanguages(MnemonicLanguages):
    """Enumerative for Monero languages."""

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
    """Class container for Monero mnemonic constants."""

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
    LANGUAGE_UNIQUE_PREFIX_LEN: Dict[MnemonicLanguages, int] = {
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
    LANGUAGE_FILES: Dict[MnemonicLanguages, str] = {
        MoneroLanguages.CHINESE_SIMPLIFIED: "wordlist/chinese_simplified.txt",
        MoneroLanguages.DUTCH: "wordlist/dutch.txt",
        MoneroLanguages.ENGLISH: "wordlist/english.txt",
        MoneroLanguages.FRENCH: "wordlist/french.txt",
        MoneroLanguages.GERMAN: "wordlist/german.txt",
        MoneroLanguages.ITALIAN: "wordlist/italian.txt",
        MoneroLanguages.JAPANESE: "wordlist/japanese.txt",
        MoneroLanguages.PORTUGUESE: "wordlist/portuguese.txt",
        MoneroLanguages.SPANISH: "wordlist/spanish.txt",
        MoneroLanguages.RUSSIAN: "wordlist/russian.txt",
    }

    # Total number of words
    WORDS_LIST_NUM: int = 1626


class MoneroMnemonic(Mnemonic):
    """Monero mnemonic class (alias for Mnemonic)."""
