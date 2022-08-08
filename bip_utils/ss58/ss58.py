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
Module for SS58 decoding/encoding.
Reference: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)
"""

# Imports
from typing import Tuple

from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.ss58.ss58_ex import SS58ChecksumError
from bip_utils.utils.crypto import Blake2b512
from bip_utils.utils.misc import BytesUtils, IntegerUtils


class SS58Const:
    """Class container for SS58 constants."""

    # Max format for simple account
    SIMPLE_ACCOUNT_FORMAT_MAX_VAL: int = 63
    # Format maximum value
    FORMAT_MAX_VAL: int = 16383
    # Reserved formats
    RESERVED_FORMATS: Tuple[int, int] = (46, 47)

    # Data length in bytes
    DATA_BYTE_LEN: int = 32

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 2
    # Checksum prefix
    CHECKSUM_PREFIX: bytes = b"SS58PRE"


class _SS58Utils:
    """Class container for SS58 utility functions."""

    @staticmethod
    def ComputeChecksum(data_bytes: bytes) -> bytes:
        """
        Compute SS58 checksum.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Computed checksum
        """
        return Blake2b512.QuickDigest(SS58Const.CHECKSUM_PREFIX + data_bytes)[:SS58Const.CHECKSUM_BYTE_LEN]


class SS58Encoder:
    """SS58 encoder class. It provides methods for encoding to SS58 format."""

    @staticmethod
    def Encode(data_bytes: bytes,
               ss58_format: int) -> str:
        """
        Encode bytes into a SS58 string.

        Args:
            data_bytes (bytes): Data bytes (32-byte length)
            ss58_format (int) : SS58 format

        Returns:
            str: SS58 encoded string

        Raises:
            ValueError: If parameters are not valid
        """

        # Check parameters
        if len(data_bytes) != SS58Const.DATA_BYTE_LEN:
            raise ValueError(f"Invalid data length ({len(data_bytes)})")
        if ss58_format < 0 or ss58_format > SS58Const.FORMAT_MAX_VAL:
            raise ValueError(f"Invalid SS58 format ({ss58_format})")
        if ss58_format in SS58Const.RESERVED_FORMATS:
            raise ValueError(f"Invalid SS58 format ({ss58_format})")

        # Simple account
        if ss58_format <= SS58Const.SIMPLE_ACCOUNT_FORMAT_MAX_VAL:
            ss58_format_bytes = IntegerUtils.ToBytes(ss58_format)
        # Full address
        else:
            # 0b00HHHHHH_MMLLLLLL -> (0b01LLLLLL, 0bHHHHHHMM)
            ss58_format_bytes = bytes([
                ((ss58_format & 0x00FC) >> 2) | 0x0040,
                (ss58_format >> 8) | ((ss58_format & 0x0003) << 6)
            ])

        # Get payload
        payload = ss58_format_bytes + data_bytes
        # Compute checksum
        checksum = _SS58Utils.ComputeChecksum(payload)
        # Encode
        return Base58Encoder.Encode(payload + checksum)


class SS58Decoder:
    """SS58 decoder class. It provides methods for decoding SS58 format."""

    @staticmethod
    def Decode(data_str: str) -> Tuple[int, bytes]:
        """
        Decode bytes from a SS58 string.

        Args:
            data_str (string): Data string

        Returns:
            tuple[int, bytes]: SS58 format and data bytes

        Raises:
            SS58ChecksumError: If checksum is not valid
            ValueError: If the string is not a valid SS58 format
        """

        # Decode string
        dec_bytes = Base58Decoder.Decode(data_str)

        # Full address
        if dec_bytes[0] & 0x40:
            ss58_format_len = 2
            ss58_format = ((dec_bytes[0] & 0x3F) << 2) | (dec_bytes[1] >> 6) | \
                          ((dec_bytes[1] & 0x3F) << 8)
        # Simple account
        else:
            ss58_format_len = 1
            ss58_format = dec_bytes[0]

        # Check format
        if ss58_format in SS58Const.RESERVED_FORMATS:
            raise ValueError(f"Invalid SS58 format ({ss58_format})")

        # Get back data and checksum
        data_bytes = dec_bytes[ss58_format_len:-SS58Const.CHECKSUM_BYTE_LEN]
        checksum_bytes = dec_bytes[-SS58Const.CHECKSUM_BYTE_LEN:]

        # Check data length
        if len(data_bytes) != SS58Const.DATA_BYTE_LEN:
            raise ValueError(f"Invalid data length ({len(data_bytes)})")

        # Compute checksum
        checksum_bytes_got = _SS58Utils.ComputeChecksum(dec_bytes[:-SS58Const.CHECKSUM_BYTE_LEN])

        # Verify checksum
        if checksum_bytes != checksum_bytes_got:
            raise SS58ChecksumError(
                f"Invalid checksum (expected {BytesUtils.ToHexString(checksum_bytes_got)}, "
                f"got {BytesUtils.ToHexString(checksum_bytes)})"
            )

        return ss58_format, data_bytes
