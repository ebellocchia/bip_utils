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

"""Module for Substrate SCALE encoding for unsigned integers."""

# Imports
from abc import ABC
from typing import Any

from bip_utils.substrate.scale.substrate_scale_enc_base import SubstrateScaleEncoderBase
from bip_utils.utils.misc import IntegerUtils


class SubstrateScaleUintEncoder(SubstrateScaleEncoderBase, ABC):
    """Substrate SCALE encoding class for unsigned integers."""

    @staticmethod
    def _EncodeWithBytesLength(value: Any,
                               bytes_len: int) -> bytes:
        """
        Encode the specified value to bytes with the specified bytes length.

        Args:
            value (any)    : Value to be encoded
            bytes_len (int): Bytes length

        Returns:
            bytes: Encoded value
        """
        if isinstance(value, str):
            value = int(value)

        max_val = (1 << (bytes_len * 8)) - 1
        if value < 0 or value > max_val:
            raise ValueError(f"Invalid integer value ({value})")
        return IntegerUtils.ToBytes(value, bytes_len, endianness="little")


class SubstrateScaleU8Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 8-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 1)


class SubstrateScaleU16Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 16-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 2)


class SubstrateScaleU32Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 32-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 4)


class SubstrateScaleU64Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 64-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 8)


class SubstrateScaleU128Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 128-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 16)


class SubstrateScaleU256Encoder(SubstrateScaleUintEncoder):
    """Substrate SCALE encoding class for 256-bit unsigned integers."""

    @classmethod
    def Encode(cls,
               value: Any) -> bytes:
        """
        Encode the specified value to bytes.

        Args:
            value (any): Value to be encoded

        Returns:
            bytes: Encoded value
        """
        return cls._EncodeWithBytesLength(value, 32)
