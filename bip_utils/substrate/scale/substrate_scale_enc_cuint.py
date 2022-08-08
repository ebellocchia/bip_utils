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

"""Module for Substrate SCALE encoding for compact unsigned integers."""

# Imports
from typing import Any

from bip_utils.substrate.scale.substrate_scale_enc_base import SubstrateScaleEncoderBase
from bip_utils.utils.misc import IntegerUtils


class SubstrateScaleCUintEncoderConst:
    """Class container for Substrate SCALE encoding for compact unsigned integers constants."""

    # Maximum values
    SINGLE_BYTE_MODE_MAX_VAL: int = 2**6 - 1
    TWO_BYTE_MODE_MAX_VAL: int = 2**14 - 1
    FOUR_BYTE_MODE_MAX_VAL: int = 2**30 - 1
    BIG_INTEGER_MODE_MAX_VAL: int = 2**536 - 1


class SubstrateScaleCUintEncoder(SubstrateScaleEncoderBase):
    """Substrate SCALE encoding for compact unsigned integers."""

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

        # Single-byte mode
        if value <= SubstrateScaleCUintEncoderConst.SINGLE_BYTE_MODE_MAX_VAL:
            return IntegerUtils.ToBytes(value << 2, 1, endianness="little")
        # Two-byte mode
        if value <= SubstrateScaleCUintEncoderConst.TWO_BYTE_MODE_MAX_VAL:
            return IntegerUtils.ToBytes((value << 2) | 0b01, 2, endianness="little")
        # Four-byte mode
        if value <= SubstrateScaleCUintEncoderConst.FOUR_BYTE_MODE_MAX_VAL:
            return IntegerUtils.ToBytes((value << 2) | 0b10, 4, endianness="little")
        # Big-integer mode
        if value <= SubstrateScaleCUintEncoderConst.BIG_INTEGER_MODE_MAX_VAL:
            value_bytes = IntegerUtils.ToBytes(value, endianness="little")
            len_bytes = IntegerUtils.ToBytes((len(value_bytes) - 4 << 2) | 0b11, 1, endianness="little")
            return len_bytes + value_bytes

        raise ValueError(f"Out of range integer value ({value})")
