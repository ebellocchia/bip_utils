# Copyright (c) 2022 Emanuele Bellocchia
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

"""Module for CRC algorithms."""

# Imports
import binascii
from typing import Union

import crcmod.predefined

from bip_utils.utils.misc import AlgoUtils, IntegerUtils


# Get the class only once for efficiency
XMODEM_CRC = crcmod.predefined.Crc("xmodem")


class Crc32:
    """
    CRC32 class.
    It computes digests using CRC32 algorithm.
    """

    @staticmethod
    def QuickDigest(data: Union[bytes, str]) -> bytes:
        """
        Compute the digest (quick version).

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed digest
        """
        return IntegerUtils.ToBytes(Crc32.QuickIntDigest(data), bytes_num=Crc32.DigestSize())

    @staticmethod
    def QuickIntDigest(data: Union[bytes, str]) -> int:
        """
        Compute the digest as integer (quick version).

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed digest
        """
        return binascii.crc32(AlgoUtils.Encode(data))   # Much faster than crcmod

    @staticmethod
    def DigestSize() -> int:
        """
        Get the digest size in bytes.

        Returns:
            int: Digest size in bytes
        """
        return 4


class XModemCrc:
    """
    XMODEM-CRC class.
    It computes digests using XMODEM-CRC algorithm.
    """

    @staticmethod
    def QuickDigest(data: Union[bytes, str]) -> bytes:
        """
        Compute the digest (quick version).

        Args:
            data (str or bytes): Data

        Returns:
            bytes: Computed digest
        """
        return XMODEM_CRC.new(AlgoUtils.Encode(data)).digest()

    @staticmethod
    def DigestSize() -> int:
        """
        Get the digest size in bytes.

        Returns:
            int: Digest size in bytes
        """
        return XMODEM_CRC.digest_size
