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

"""Module for Monero Polyseed mnemonic encoding."""

# Imports
import time

from typing_extensions import override

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedCoins,
    MoneroPolyseedLanguages,
    MoneroPolyseedMnemonic,
    MoneroPolyseedMnemonicConst,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_utils import (
    MoneroPolyseedDecodedData,
    MoneroPolyseedGf,
    MoneroPolyseedMnemonicUtils,
)
from bip_utils.utils.mnemonic import Mnemonic, MnemonicEncoderBase


class MoneroPolyseedMnemonicEncoder(MnemonicEncoderBase):
    """
    Monero Polyseed mnemonic encoder class.
    It encodes seed data to a 16-word mnemonic phrase.
    """

    m_lang: MoneroPolyseedLanguages

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
        if not isinstance(lang, MoneroPolyseedLanguages):
            raise TypeError("Language is not a MoneroPolyseedLanguages enum")
        super().__init__(lang.value, Bip39WordsListGetter)
        self.m_lang = lang

    @override
    def Encode(self,
               entropy_bytes: bytes) -> Mnemonic:
        """
        Encode entropy bytes to mnemonic phrase using current time as birthday.

        Args:
            entropy_bytes (bytes): Secret bytes (19 bytes)

        Returns:
            Mnemonic: Encoded mnemonic phrase

        Raises:
            ValueError: If the entropy length is not valid
        """
        return self.EncodeWithData(entropy_bytes, int(time.time()))

    def EncodeWithData(self,
                       entropy_bytes: bytes,
                       birthday: int,
                       features: int = 0,
                       coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO) -> Mnemonic:
        """
        Encode seed data to mnemonic phrase.

        Args:
            entropy_bytes (bytes)            : Secret bytes (19 bytes)
            birthday (int)                   : Unix timestamp or raw 10-bit encoded birthday
            features (int, optional)         : User feature flags (0-7, default: 0)
            coin (MoneroPolyseedCoins, optional): Target coin for domain separation (default: MONERO)

        Returns:
            Mnemonic: Encoded mnemonic phrase

        Raises:
            ValueError: If the entropy length is not valid
        """
        # Validate entropy length
        if len(entropy_bytes) != MoneroPolyseedMnemonicConst.SECRET_SIZE:
            raise ValueError(f"Entropy byte length ({len(entropy_bytes)}) is not valid")

        # Clear top 2 bits of last byte
        secret = bytearray(entropy_bytes)
        secret[MoneroPolyseedMnemonicConst.SECRET_SIZE - 1] &= MoneroPolyseedMnemonicConst.CLEAR_MASK

        # Encode birthday from timestamp if needed
        if birthday > MoneroPolyseedMnemonicConst.DATE_MASK:
            birthday = MoneroPolyseedMnemonicUtils.BirthdayEncode(birthday)

        # Sanitize features to user-accessible bits only
        features = features & MoneroPolyseedMnemonicConst.USER_FEATURES_MASK

        # Build data structure
        data = MoneroPolyseedDecodedData(
            secret=bytes(secret),
            birthday=birthday,
            features=features,
            checksum=0,
        )

        # Convert to polynomial and calculate checksum
        coeffs = MoneroPolyseedMnemonicUtils.DataToPoly(data)
        coeffs = MoneroPolyseedGf.PolyEncode(coeffs)

        # Apply coin domain separation
        coeffs[MoneroPolyseedMnemonicConst.POLY_NUM_CHECK_DIGITS] ^= int(coin)

        # Map coefficients to words
        words = [self.m_words_list.GetWordAtIdx(c) for c in coeffs]

        return MoneroPolyseedMnemonic.FromList(words)

    def EncodeData(self,
                   data: MoneroPolyseedDecodedData,
                   coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO) -> Mnemonic:
        """
        Encode decoded data to mnemonic phrase.

        Args:
            data (MoneroPolyseedDecodedData)    : Decoded polyseed data
            coin (MoneroPolyseedCoins, optional): Target coin for domain separation (default: MONERO)

        Returns:
            Mnemonic: Encoded mnemonic phrase
        """
        # Convert to polynomial with existing checksum
        coeffs = MoneroPolyseedMnemonicUtils.DataToPoly(data)
        coeffs[0] = data.checksum

        # Apply coin domain separation
        coeffs[MoneroPolyseedMnemonicConst.POLY_NUM_CHECK_DIGITS] ^= int(coin)

        # Map coefficients to words
        words = [self.m_words_list.GetWordAtIdx(c) for c in coeffs]

        return MoneroPolyseedMnemonic.FromList(words)
