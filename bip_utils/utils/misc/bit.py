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

"""Module with some bits utility functions."""

# Imports
from typing import List, Optional, Union


class BitUtils:
    """Class container for bit utility functions."""

    @staticmethod
    def IsBitSet(value: int,
                 bit_num: int) -> bool:
        """
        Get if the specified bit is set.

        Args:
            value (int)  : Value
            bit_num (int): Bit number to check

        Returns:
            bool: True if bit is set, false otherwise
        """
        return (value & (1 << bit_num)) != 0

    @staticmethod
    def SetBit(value: int,
               bit_num: int) -> int:
        """
        Set the specified bit.

        Args:
            value (int)  : Value
            bit_num (int): Bit number to check

        Returns:
            int: Value with the specified bit set
        """
        value = value | (1 << bit_num)
        return value

    @staticmethod
    def ResetBit(value: int,
                 bit_num: int) -> int:
        """
        Reset the specified bit.

        Args:
            value (int)  : Value
            bit_num (int): Bit number to check

        Returns:
            int: Value with the specified bit reset
        """
        value = value & ~(1 << bit_num)
        return value

    @staticmethod
    def Convert(data: Union[bytes, List[int]],
                from_bits: int,
                to_bits: int,
                pad: bool = True) -> Optional[List[int]]:
        """
        Perform generic bits conversion.

        Args:
            data (list or bytes): Data to be converted
            from_bits (int)     : Number of bits to start from
            to_bits (int)       : Number of bits at the end
            pad (bool, optional): True if data must be padded, false otherwise

        Returns:
            list: List of converted bits, None in case of errors
        """

        acc = 0
        bits = 0
        ret = []
        maxv = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1

        for value in data:
            if value < 0 or (value >> from_bits):
                return None
            acc = ((acc << from_bits) | value) & max_acc
            bits += from_bits
            while bits >= to_bits:
                bits -= to_bits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (to_bits - bits)) & maxv)
        elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
            return None

        return ret
