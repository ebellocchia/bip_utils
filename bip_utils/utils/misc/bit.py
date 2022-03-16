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
        Perform bit conversion.
        The function takes the input data (list of integers or byte sequence) and convert every value from
        the specified number of bits to the specified one.
        It returns a list of integer where every number is less than 2^to_bits.

        Args:
            data (list or bytes): Data to be converted
            from_bits (int)     : Number of bits to start from
            to_bits (int)       : Number of bits at the end
            pad (bool, optional): True if data must be padded with zeros, false otherwise

        Returns:
            list: List of converted values, None in case of errors
        """
        max_out_val = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1

        acc = 0
        bits = 0
        ret = []

        for value in data:
            # Value shall not be less than zero or greater than 2^from_bits
            if value < 0 or (value >> from_bits):
                return None
            # Continue accumulating until greater than to_bits
            acc = ((acc << from_bits) | value) & max_acc
            bits += from_bits
            while bits >= to_bits:
                bits -= to_bits
                ret.append((acc >> bits) & max_out_val)
        if pad:
            if bits:
                # Pad the value with zeros to reach to_bits
                ret.append((acc << (to_bits - bits)) & max_out_val)
        elif bits >= from_bits or ((acc << (to_bits - bits)) & max_out_val):
            return None

        return ret
