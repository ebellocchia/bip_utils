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

"""Module for Monero Polyseed mnemonic validation."""

# Imports
from typing import Optional

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedCoins,
    MoneroPolyseedLanguages,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_decoder import MoneroPolyseedMnemonicDecoder
from bip_utils.utils.mnemonic import MnemonicValidator


class MoneroPolyseedMnemonicValidator(MnemonicValidator):
    """
    Monero Polyseed mnemonic validator class.
    It validates a Polyseed mnemonic phrase.
    """

    def __init__(self,
                 coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO,
                 lang: Optional[MoneroPolyseedLanguages] = None) -> None:
        """
        Construct class.

        Args:
            coin (MoneroPolyseedCoins, optional)    : Coin for domain separation (default: MONERO)
            lang (MoneroPolyseedLanguages, optional): Language, None for automatic detection

        Raises:
            TypeError: If the language is not a MoneroPolyseedLanguages enum
            ValueError: If loaded words list is not valid
        """
        super().__init__(MoneroPolyseedMnemonicDecoder(coin, lang))
