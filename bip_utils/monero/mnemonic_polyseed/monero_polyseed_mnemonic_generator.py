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

"""Module for Monero Polyseed mnemonic generation."""

# Imports
import time
from typing import Optional

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_entropy_generator import MoneroPolyseedEntropyGenerator
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedCoins,
    MoneroPolyseedLanguages,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_encoder import MoneroPolyseedMnemonicEncoder
from bip_utils.utils.mnemonic import Mnemonic


class MoneroPolyseedMnemonicGenerator:
    """
    Monero Polyseed mnemonic generator class.
    It generates Polyseed mnemonics from entropy or randomly.
    """

    m_mnemonic_encoder: MoneroPolyseedMnemonicEncoder

    def __init__(self,
                 lang: MoneroPolyseedLanguages = MoneroPolyseedLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            lang (MoneroPolyseedLanguages, optional): Language (default: English)

        Raises:
            TypeError: If the language is not a MoneroPolyseedLanguages enum
            ValueError: If loaded words list is not valid
        """
        self.m_mnemonic_encoder = MoneroPolyseedMnemonicEncoder(lang)

    def FromEntropy(self,
                    entropy_bytes: bytes,
                    birthday: Optional[int] = None,
                    features: int = 0,
                    coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO) -> Mnemonic:
        """
        Generate mnemonic from provided entropy bytes.

        Args:
            entropy_bytes (bytes)            : Secret bytes (19 bytes)
            birthday (int, optional)         : Unix timestamp or raw 10-bit encoded birthday (default: current time)
            features (int, optional)         : User feature flags (0-7, default: 0)
            coin (MoneroPolyseedCoins, optional): Target coin (default: MONERO)

        Returns:
            Mnemonic: Generated mnemonic

        Raises:
            ValueError: If the entropy length is not valid
        """
        if birthday is None:
            birthday = int(time.time())
        return self.m_mnemonic_encoder.EncodeWithData(entropy_bytes, birthday, features, coin)

    def FromRandom(self,
                   birthday: Optional[int] = None,
                   features: int = 0,
                   coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO) -> Mnemonic:
        """
        Generate mnemonic from random entropy.

        Args:
            birthday (int, optional)         : Unix timestamp or raw 10-bit encoded birthday (default: current time)
            features (int, optional)         : User feature flags (0-7, default: 0)
            coin (MoneroPolyseedCoins, optional): Target coin (default: MONERO)

        Returns:
            Mnemonic: Generated mnemonic
        """
        entropy = MoneroPolyseedEntropyGenerator().Generate()
        return self.FromEntropy(entropy, birthday, features, coin)
