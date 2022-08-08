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

"""Module for Algorand mnemonic entropy generation."""

# Imports
from enum import IntEnum, unique
from typing import List, Union

from bip_utils.utils.mnemonic import EntropyGenerator


@unique
class AlgorandEntropyBitLen(IntEnum):
    """Enumerative for Algorand entropy bit lengths."""

    BIT_LEN_256 = 256


class AlgorandEntropyGeneratorConst:
    """Class container for Algorand entropy generator constants."""

    # Accepted entropy lengths in bit
    ENTROPY_BIT_LEN: List[AlgorandEntropyBitLen] = [
        AlgorandEntropyBitLen.BIT_LEN_256,
    ]


class AlgorandEntropyGenerator(EntropyGenerator):
    """
    Algorand entropy generator class.
    It generates random entropy bytes.
    """

    def __init__(self,
                 bit_len: Union[int, AlgorandEntropyBitLen] = AlgorandEntropyBitLen.BIT_LEN_256) -> None:
        """
        Construct class.

        Args:
            bit_len (int or AlgorandEntropyBitLen, optional): Entropy length in bits (default: 256)

        Raises:
            ValueError: If the bit length is not valid
        """
        if not self.IsValidEntropyBitLen(bit_len):
            raise ValueError(f"Entropy bit length is not valid ({bit_len})")
        super().__init__(bit_len)

    @staticmethod
    def IsValidEntropyBitLen(bit_len: int) -> bool:
        """
        Get if the specified entropy bit length is valid.

        Args:
            bit_len (int): Entropy length in bits

        Returns:
            bool: True if valid, false otherwise
        """
        return bit_len in AlgorandEntropyGeneratorConst.ENTROPY_BIT_LEN

    @staticmethod
    def IsValidEntropyByteLen(byte_len: int) -> bool:
        """
        Get if the specified entropy byte length is valid.

        Args:
            byte_len (int): Entropy length in bytes

        Returns:
            bool: True if valid, false otherwise
        """
        return AlgorandEntropyGenerator.IsValidEntropyBitLen(byte_len * 8)
