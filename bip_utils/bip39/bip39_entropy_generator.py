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


# Imports
import os
from enum import IntEnum, unique
from typing import List, Union


@unique
class Bip39EntropyBitLen(IntEnum):
    """ Enumerative for BIP-0039 entropy bit lengths. """

    BIT_LEN_128 = 128,
    BIT_LEN_160 = 160,
    BIT_LEN_192 = 192,
    BIT_LEN_224 = 224,
    BIT_LEN_256 = 256,


class Bip39EntropyGeneratorConst:
    """ Class container for BIP39 entropy generator constants. """

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[Bip39EntropyBitLen] = [
        Bip39EntropyBitLen.BIT_LEN_128,
        Bip39EntropyBitLen.BIT_LEN_160,
        Bip39EntropyBitLen.BIT_LEN_192,
        Bip39EntropyBitLen.BIT_LEN_224,
        Bip39EntropyBitLen.BIT_LEN_256,
    ]


class Bip39EntropyGenerator:
    """ Entropy generator class. It generates random entropy bytes with the specified length. """

    def __init__(self,
                 bits_len: Union[int, Bip39EntropyBitLen]) -> None:
        """ Construct class by specifying the bits length.

        Args:
            bits_len (int or Bip39EntropyBitLen): Entropy length in bits

        Raises:
            ValueError: If the bit length is not valid
        """
        if not self.IsValidEntropyBitLen(bits_len):
            raise ValueError("Entropy bit length is not valid (%d)" % bits_len)
        self.m_bits_len = bits_len

    def Generate(self) -> bytes:
        """ Generate random entropy bytes with the length specified during construction.

        Returns:
            bytes: Generated entropy bytes
        """
        return os.urandom(self.m_bits_len // 8)

    @staticmethod
    def IsValidEntropyBitLen(bits_len: Union[int, Bip39EntropyBitLen]) -> bool:
        """ Get if the specified entropy bit length is valid.

        Args:
            bits_len (int or Bip39EntropyBitLen): Entropy length in bits

        Returns:
            bool: True if valid, false otherwise
        """
        return bits_len in Bip39EntropyGeneratorConst.ENTROPY_BIT_LEN

    @staticmethod
    def IsValidEntropyByteLen(bytes_len: int) -> bool:
        """ Get if the specified entropy byte length is valid.

        Args:
            bytes_len (int): Entropy length in bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return Bip39EntropyGenerator.IsValidEntropyBitLen(bytes_len * 8)
