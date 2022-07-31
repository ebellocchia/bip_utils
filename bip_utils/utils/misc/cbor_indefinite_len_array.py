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

"""
Module for CBOR decoding/encoding indefinite length arrays.
Indefinite length arrays are encoded without writing the array length, so elements shall be read until
the termination byte is found.
"""

# Imports
from typing import List, Sequence
import cbor2
from bip_utils.utils.misc.integer import IntegerUtils


class CborIndefiniteLenArrayConst:
    """Class container for CBOR indefinite length arrays constants."""

    # Identifiers for integer types
    CBOR_UINT8: int = 24
    CBOR_UINT16: int = 25
    CBOR_UINT32: int = 26
    CBOR_UINT64: int = 27

    # Begin/End identifiers
    BEGIN_VAL: bytes = 0x9F
    END_VAL: bytes = 0xFF
    BEGIN_BYTE: bytes = IntegerUtils.ToBytes(0x9F)
    END_BYTE: bytes = IntegerUtils.ToBytes(0xFF)


class CborIndefiniteLenArrayDecoder:
    """
    CBOR indefinite length arrays decoder.
    It decodes bytes back to array.
    """

    @staticmethod
    def Decode(enc_bytes: bytes) -> List[int]:
        """
        CBOR-decode the specified bytes.

        Args:
            enc_bytes (bytes): Encoded bytes

        Returns:
            list[int]: List of integers

        Raises:
            ValueError: If encoding is not valid
        """

        # Check for validity
        if len(enc_bytes) < 3:
            raise ValueError(f"Invalid length ({len(enc_bytes)})")
        if enc_bytes[0] != CborIndefiniteLenArrayConst.BEGIN_VAL:
            raise ValueError(f"Invalid first byte ({enc_bytes[0]})")
        if enc_bytes[-1] != CborIndefiniteLenArrayConst.END_VAL:
            raise ValueError(f"Invalid last byte ({enc_bytes[-1]})")

        # Continue to decode elements until the end value is found
        i = 1
        int_elems = []
        while True:
            # Get current byte
            if i >= len(enc_bytes):
                raise ValueError("Invalid encoding (index overflow)")
            curr_byte = enc_bytes[i]
            if curr_byte == CborIndefiniteLenArrayConst.END_VAL:
                break
            # Get current length
            if curr_byte == CborIndefiniteLenArrayConst.CBOR_UINT8:
                curr_len = 2
            elif curr_byte == CborIndefiniteLenArrayConst.CBOR_UINT16:
                curr_len = 3
            elif curr_byte == CborIndefiniteLenArrayConst.CBOR_UINT32:
                curr_len = 5
            elif curr_byte == CborIndefiniteLenArrayConst.CBOR_UINT64:
                curr_len = 9
            else:
                curr_len = 1
            # CBOR-decode the current integer
            int_elems.append(cbor2.loads(enc_bytes[i:i + curr_len]))
            # Move forward
            i += curr_len

        return int_elems


class CborIndefiniteLenArrayEncoder:
    """
    CBOR indefinite length arrays encoder.
    It encodes indefinite length arrays to bytes.
    """

    @staticmethod
    def Encode(int_seq: Sequence[int]) -> bytes:
        """
        CBOR-encode the specified elements.

        Args:
            int_seq (sequence[int]): Collection of integers

        Returns:
            bytes: CBOR-encoded bytes
        """
        return (CborIndefiniteLenArrayConst.BEGIN_BYTE
                + b"".join([cbor2.dumps(p) for p in int_seq])
                + CborIndefiniteLenArrayConst.END_BYTE)
