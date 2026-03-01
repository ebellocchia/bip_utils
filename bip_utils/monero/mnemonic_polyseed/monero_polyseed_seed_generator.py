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

"""Module for Monero Polyseed seed generation."""

# Imports
import struct
from typing import Optional, Union

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import (
    MoneroPolyseedCoins,
    MoneroPolyseedLanguages,
    MoneroPolyseedMnemonicConst,
)
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_decoder import MoneroPolyseedMnemonicDecoder
from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic_utils import MoneroPolyseedDecodedData
from bip_utils.utils.crypto import Pbkdf2HmacSha256
from bip_utils.utils.mnemonic import Mnemonic


class MoneroPolyseedSeedGenerator:
    """
    Monero Polyseed seed generator class.
    It generates a 32-byte key from a Polyseed mnemonic via PBKDF2-HMAC-SHA256.
    """

    m_data: MoneroPolyseedDecodedData
    m_coin: MoneroPolyseedCoins

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 coin: MoneroPolyseedCoins = MoneroPolyseedCoins.MONERO,
                 lang: Optional[MoneroPolyseedLanguages] = None) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object)       : Mnemonic
            coin (MoneroPolyseedCoins, optional)    : Coin for domain separation (default: MONERO)
            lang (MoneroPolyseedLanguages, optional): Language, None for automatic detection

        Raises:
            MnemonicChecksumError: If checksum is not valid
            ValueError: If mnemonic is not valid
        """
        self.m_data = MoneroPolyseedMnemonicDecoder(coin, lang).DecodeWithData(mnemonic)
        self.m_coin = coin

    def Generate(self) -> bytes:
        """
        Generate 32-byte seed key via PBKDF2-HMAC-SHA256.

        The password is the 19-byte secret zero-padded to 32 bytes.
        The salt is: "POLYSEED key 0x00 0xff 0xff 0xff" + coin(4 LE) + birthday(4 LE) + features(4 LE) + zeros(4)

        Returns:
            bytes: Generated 32-byte seed
        """
        # Build password: secret padded to 32 bytes
        padding = b"\x00" * (MoneroPolyseedMnemonicConst.SECRET_BUFFER_SIZE - MoneroPolyseedMnemonicConst.SECRET_SIZE)
        password = self.m_data.secret + padding

        # Build salt (32 bytes)
        salt = bytearray(32)
        salt[0:12] = MoneroPolyseedMnemonicConst.KDF_KEY_SALT_PREFIX
        salt[12] = 0x00
        salt[13] = 0xFF
        salt[14] = 0xFF
        salt[15] = 0xFF
        struct.pack_into("<I", salt, 16, int(self.m_coin))
        struct.pack_into("<I", salt, 20, self.m_data.birthday)
        struct.pack_into("<I", salt, 24, self.m_data.features)
        # bytes 28-31 remain 0x00

        return Pbkdf2HmacSha256.DeriveKey(
            password=password,
            salt=bytes(salt),
            itr_num=MoneroPolyseedMnemonicConst.KDF_NUM_ITERATIONS,
            dklen=MoneroPolyseedMnemonicConst.KDF_KEY_SIZE,
        )
