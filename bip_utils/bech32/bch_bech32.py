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

"""
Module for BitcoinCash bech32 decoding/encoding.
Reference: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md.
"""

# Imports
from typing import List, Tuple
from bip_utils.bech32.bech32_base import Bech32DecoderBase, Bech32EncoderBase, Bech32BaseUtils
from bip_utils.bech32.bech32_ex import Bech32FormatError
from bip_utils.utils.misc import ConvUtils


class BchBech32Const:
    """Class container for Bitcoin Cash Bech32 constants."""

    # Separator
    SEPARATOR: str = ":"
    # Checkum length in bytes
    CHECKSUM_BYTE_LEN: int = 8
    # Minimum data length in bytes
    DATA_MIN_BYTE_LEN: int = 2
    # Maximum data length in bytes
    DATA_MAX_BYTE_LEN: int = 40


class BchBech32Utils:
    """Class container for Bitcoin Cash utility functions."""

    @staticmethod
    def PolyMod(values: List[int]) -> int:
        """
        Computes the polynomial modulus.

        Args:
            values (list): List of polynomial coefficients

        Returns:
            int: Computed modulus
        """

        # Generator polynomial
        generator = [
            (0x01, 0x98f2bc8e61),
            (0x02, 0x79b76d99e2),
            (0x04, 0xf33e5fb3c4),
            (0x08, 0xae2eabe2a8),
            (0x10, 0x1e4f43e470)
        ]
        # Compute modulus
        chk = 1
        for value in values:
            top = chk >> 35
            chk = ((chk & 0x07ffffffff) << 5) ^ value
            for i in generator:
                if top & i[0] != 0:
                    chk ^= i[1]

        return chk ^ 1

    @staticmethod
    def HrpExpand(hrp: str) -> List[int]:
        """
        Expand the HRP into values for checksum computation.

        Args:
            hrp (str): HRP

        Returns:
            list: Expanded HRP values
        """
        # [lower 5 bits of each character] + [0]
        return [ord(x) & 0x1f for x in hrp] + [0]

    @staticmethod
    def ComputeChecksum(hrp: str,
                        data: List[int]) -> List[int]:
        """
        Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            list: Computed checksum
        """

        values = BchBech32Utils.HrpExpand(hrp) + data
        polymod = BchBech32Utils.PolyMod(values + [0, 0, 0, 0, 0, 0, 0, 0])
        return [(polymod >> 5 * (7 - i)) & 0x1f for i in range(BchBech32Const.CHECKSUM_BYTE_LEN)]

    @staticmethod
    def VerifyChecksum(hrp: str,
                       data: List[int]) -> bool:
        """
        Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str) : HRP
            data (list): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        return BchBech32Utils.PolyMod(BchBech32Utils.HrpExpand(hrp) + data) == 0


class BchBech32Encoder(Bech32EncoderBase):
    """
    Bitcoin Cash Bech32 encoder class.
    It provides methods for encoding to Bitcoin Cash Bech32 format.
    """

    @staticmethod
    def Encode(hrp: str,
               net_ver: bytes,
               data: bytes) -> str:
        """
        Encode to Bitcoin Cash Bech32.

        Args:
            hrp (str)      : HRP
            net_ver (bytes): Net version
            data (bytes)   : Data

        Returns:
            str: Encoded address

        Raises:
            Bech32FormatError: If the data is not valid
        """

        return BchBech32Encoder._EncodeBech32(hrp,
                                              Bech32BaseUtils.ConvertToBase32(net_ver + data),
                                              BchBech32Const.SEPARATOR)

    @staticmethod
    def _ComputeChecksum(hrp: str,
                         data: List[int]) -> List[int]:
        """
        Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            list: Computed checksum
        """
        return BchBech32Utils.ComputeChecksum(hrp, data)


class BchBech32Decoder(Bech32DecoderBase):
    """
    Bitcoin Cash Bech32 decoder class.
    It provides methods for decoding Bitcoin Cash Bech32 format.
    """

    @staticmethod
    def Decode(hrp: str,
               addr: str) -> Tuple[int, bytes]:
        """
        Decode from Bitcoin Cash Bech32.

        Args:
            hrp (str) : Human readable part
            addr (str): Address

        Returns:
            tuple: Net version (index 0) and data (index 1)

        Raises:
            Bech32FormatError: If the bech32 string is not valid
            Bech32ChecksumError: If the checksum is not valid
        """

        # Decode string
        hrpgot, data = BchBech32Decoder._DecodeBech32(addr, BchBech32Const.SEPARATOR, BchBech32Const.CHECKSUM_BYTE_LEN)

        # Check HRP
        if hrpgot != hrp:
            raise Bech32FormatError(f"Invalid format (HRP not valid, expected {hrp}, got {hrpgot})")

        # Convert back from base32
        conv_data = Bech32BaseUtils.ConvertFromBase32(data)

        # Check converted data
        if (len(conv_data) < BchBech32Const.DATA_MIN_BYTE_LEN
                or len(conv_data) > BchBech32Const.DATA_MAX_BYTE_LEN):
            raise Bech32FormatError(f"Invalid format (length not valid: {len(conv_data)})")

        return conv_data[0], ConvUtils.ListToBytes(conv_data[1:])

    @staticmethod
    def _VerifyChecksum(hrp: str,
                        data: List[int]) -> bool:
        """
        Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str) : HRP
            data (list): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        return BchBech32Utils.VerifyChecksum(hrp, data)
