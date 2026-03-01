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

"""Module for Monero Polyseed entropy generation."""

# Imports
import os
from enum import IntEnum, unique
from typing import List, Union

from typing_extensions import override

from bip_utils.monero.mnemonic_polyseed.monero_polyseed_mnemonic import MoneroPolyseedMnemonicConst
from bip_utils.utils.mnemonic import EntropyGenerator


@unique
class MoneroPolyseedEntropyBitLen(IntEnum):
    """Enumerative for Monero Polyseed entropy bit lengths."""

    BIT_LEN_150 = 150


class MoneroPolyseedEntropyGeneratorConst:
    """Class container for Monero Polyseed entropy generator constants."""

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[MoneroPolyseedEntropyBitLen] = [
        MoneroPolyseedEntropyBitLen.BIT_LEN_150,
    ]


class MoneroPolyseedEntropyGenerator(EntropyGenerator):
    """
    Monero Polyseed entropy generator class.
    It generates random entropy bytes (19 bytes, 150 bits) with top 2 bits of the last byte cleared.
    """

    def __init__(self,
                 bit_len: Union[int, MoneroPolyseedEntropyBitLen] = MoneroPolyseedEntropyBitLen.BIT_LEN_150) -> None:
        """
        Construct class.

        Args:
            bit_len (int or MoneroPolyseedEntropyBitLen): Entropy length in bits

        Raises:
            ValueError: If the bit length is not valid
        """
        if not self.IsValidEntropyBitLen(bit_len):
            raise ValueError(f"Entropy bit length is not valid ({bit_len})")
        super().__init__(bit_len)

    @override
    def Generate(self) -> bytes:
        """
        Generate random entropy bytes (19 bytes with top 2 bits of the last byte cleared).

        Returns:
            bytes: Generated entropy bytes
        """
        entropy = bytearray(os.urandom(MoneroPolyseedMnemonicConst.SECRET_SIZE))
        entropy[MoneroPolyseedMnemonicConst.SECRET_SIZE - 1] &= MoneroPolyseedMnemonicConst.CLEAR_MASK
        return bytes(entropy)

    @staticmethod
    def IsValidEntropyBitLen(bit_len: Union[int, MoneroPolyseedEntropyBitLen]) -> bool:
        """
        Get if the specified entropy bit length is valid.

        Args:
            bit_len (int or MoneroPolyseedEntropyBitLen): Entropy length in bits

        Returns:
            bool: True if valid, false otherwise
        """
        return bit_len in MoneroPolyseedEntropyGeneratorConst.ENTROPY_BIT_LEN

    @staticmethod
    def IsValidEntropyByteLen(byte_len: int) -> bool:
        """
        Get if the specified entropy byte length is valid.

        Args:
            byte_len (int): Entropy length in bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return byte_len == MoneroPolyseedMnemonicConst.SECRET_SIZE
