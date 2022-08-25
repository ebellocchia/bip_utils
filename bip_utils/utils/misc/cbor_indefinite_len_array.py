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

NOTE: encoding of values greater than 2^64 is not supported.
"""

# Imports
from enum import IntEnum, unique
from typing import Dict, List, Sequence

import cbor2

from bip_utils.utils.misc.integer import IntegerUtils


@unique
class CborIds(IntEnum):
    """Enumerative for CBOR identifiers."""

    UINT8 = 24
    UINT16 = 25
    UINT32 = 26
    UINT64 = 27
    INDEF_LEN_ARRAY_START = 0x9F
    INDEF_LEN_ARRAY_END = 0xFF


class CborIndefiniteLenArrayConst:
    """Class container for CBOR indefinite length arrays constants."""

    # CBOR uint IDs to byte length
    UINT_IDS_TO_BYTE_LEN: Dict[int, int] = {
        CborIds.UINT8: 2,
        CborIds.UINT16: 3,
        CborIds.UINT32: 5,
        CborIds.UINT64: 9,
    }


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
        if enc_bytes[0] != CborIds.INDEF_LEN_ARRAY_START:
            raise ValueError(f"Invalid first byte ({enc_bytes[0]})")
        if enc_bytes[-1] != CborIds.INDEF_LEN_ARRAY_END:
            raise ValueError(f"Invalid last byte ({enc_bytes[-1]})")

        # Continue to decode elements until the end value is found
        i = 1
        int_elems = []
        while True:
            # Get current byte
            if i >= len(enc_bytes):
                raise ValueError("Invalid encoding (index overflow)")
            curr_val = enc_bytes[i]
            if curr_val == CborIds.INDEF_LEN_ARRAY_END:
                break
            # Get current length (1-byte if ID is not found)
            curr_len = CborIndefiniteLenArrayConst.UINT_IDS_TO_BYTE_LEN.get(curr_val, 1)
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
        return (IntegerUtils.ToBytes(CborIds.INDEF_LEN_ARRAY_START, bytes_num=1)
                + b"".join([cbor2.dumps(p) for p in int_seq])
                + IntegerUtils.ToBytes(CborIds.INDEF_LEN_ARRAY_END, bytes_num=1))
