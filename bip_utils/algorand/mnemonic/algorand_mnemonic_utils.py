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

"""Module for Algorand mnemonic utility classes."""

# Imports
from typing import List, Optional, Union

from bip_utils.algorand.mnemonic.algorand_mnemonic import AlgorandMnemonicConst
from bip_utils.utils.crypto import Sha512_256


class AlgorandMnemonicUtils:
    """Class container for Algorand mnemonic utility functions."""

    @staticmethod
    def ComputeChecksum(data_bytes: bytes) -> bytes:
        """
        Compute checksum.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed checksum
        """
        return Sha512_256.QuickDigest(data_bytes)[:AlgorandMnemonicConst.CHECKSUM_BYTE_LEN]

    @staticmethod
    def ComputeChecksumWordIndex(data_bytes: bytes) -> int:
        """
        Compute checksum word index.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            str: Computed checksum word index
        """

        # Compute checksum and convert it to 11-bit
        chksum = AlgorandMnemonicUtils.ComputeChecksum(data_bytes)
        chksum_11bit = AlgorandMnemonicUtils.ConvertBits(chksum, 8, 11)
        # Cannot be None by converting bytes from 8-bit to 11-bit
        assert chksum_11bit is not None

        return chksum_11bit[0]

    @staticmethod
    def ConvertBits(data: Union[bytes, List[int]],
                    from_bits: int,
                    to_bits: int) -> Optional[List[int]]:
        """
        Perform bit conversion.
        The function takes the input data (list of integers or byte sequence) and convert every value from
        the specified number of bits to the specified one.
        It returns a list of integer where every number is less than 2^to_bits.

        Args:
            data (list[int] or bytes): Data to be converted
            from_bits (int)          : Number of bits to start from
            to_bits (int)            : Number of bits to end with

        Returns:
            list[int]: List of converted values, None in case of errors
        """
        max_out_val = (1 << to_bits) - 1

        acc = 0
        bits = 0
        ret = []

        for value in data:
            # Value shall not be less than zero or greater than 2^from_bits
            if value < 0 or (value >> from_bits):
                return None
            # Continue accumulating until greater than to_bits
            acc |= value << bits
            bits += from_bits
            while bits >= to_bits:
                ret.append(acc & max_out_val)
                acc = acc >> to_bits
                bits -= to_bits

        if bits != 0:
            ret.append(acc & max_out_val)

        return ret
