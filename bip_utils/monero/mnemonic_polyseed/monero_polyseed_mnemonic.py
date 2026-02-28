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

"""Module for Monero Polyseed mnemonic."""

# Imports
from enum import IntEnum, unique
from typing import List

from bip_utils.bip.bip39 import Bip39Languages
from bip_utils.utils.mnemonic import Mnemonic, MnemonicLanguages


@unique
class MoneroPolyseedWordsNum(IntEnum):
    """Enumerative for Monero Polyseed words number."""

    WORDS_NUM_16 = 16


@unique
class MoneroPolyseedLanguages(MnemonicLanguages):
    """Enumerative for Monero Polyseed languages."""

    CHINESE_SIMPLIFIED = Bip39Languages.CHINESE_SIMPLIFIED
    CHINESE_TRADITIONAL = Bip39Languages.CHINESE_TRADITIONAL
    ENGLISH = Bip39Languages.ENGLISH
    FRENCH = Bip39Languages.FRENCH
    ITALIAN = Bip39Languages.ITALIAN
    KOREAN = Bip39Languages.KOREAN
    PORTUGUESE = Bip39Languages.PORTUGUESE


@unique
class MoneroPolyseedCoins(IntEnum):
    """Enumerative for Monero Polyseed coins."""

    MONERO = 0
    AEON = 1
    WOWNERO = 2


class MoneroPolyseedMnemonicConst:
    """Class container for Monero Polyseed mnemonic constants."""

    # Accepted mnemonic word numbers
    MNEMONIC_WORD_NUM: List[MoneroPolyseedWordsNum] = [
        MoneroPolyseedWordsNum.WORDS_NUM_16,
    ]

    # GF(2048) parameters
    GF_BITS: int = 11
    GF_SIZE: int = 2048
    GF_MASK: int = 2047
    POLY_NUM_CHECK_DIGITS: int = 1
    NUM_WORDS: int = 16

    # Secret parameters
    SECRET_BITS: int = 150
    SECRET_SIZE: int = 19
    SECRET_BUFFER_SIZE: int = 32
    CLEAR_BITS: int = 2
    CLEAR_MASK: int = 0x3F

    # Date parameters
    DATE_BITS: int = 10
    DATE_MASK: int = 1023
    EPOCH: int = 1635768000
    TIME_STEP: int = 2629746

    # Feature parameters
    FEATURE_BITS: int = 5
    FEATURE_MASK: int = 31
    USER_FEATURES: int = 3
    USER_FEATURES_MASK: int = 7
    ENCRYPTED_MASK: int = 16

    # Share bits per word (from secret)
    SHARE_BITS: int = 10

    # Data words (non-check)
    DATA_WORDS: int = 15

    # KDF parameters
    KDF_NUM_ITERATIONS: int = 10000
    KDF_KEY_SIZE: int = 32
    KDF_KEY_SALT_PREFIX: bytes = b"POLYSEED key"
    KDF_MASK_SALT: bytes = b"POLYSEED mask\x00\xff\xff"

    # GF(2048) multiplication-by-2 lookup table
    MUL2_TABLE: List[int] = [5, 7, 1, 3, 13, 15, 9, 11]


class MoneroPolyseedMnemonic(Mnemonic):
    """Monero Polyseed mnemonic class (alias for Mnemonic)."""
