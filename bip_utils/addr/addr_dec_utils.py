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

"""Module with utility functions for address decoding."""

# Imports
from enum import Enum, auto, unique
from typing import Callable, Tuple, Type, TypeVar, Union

from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import BytesUtils


BytesOrStr = TypeVar("BytesOrStr", bytes, str)


@unique
class ChecksumPositions(Enum):
    """Enumerative for checksum positions."""

    BEGINNING = auto()
    END = auto()


class AddrDecUtils:
    """Class container for address decoding utility functions."""

    @staticmethod
    def ValidateAndRemovePrefix(addr: BytesOrStr,
                                prefix: BytesOrStr) -> BytesOrStr:
        """
        Validate and remove prefix from an address.

        Args:
            addr (bytes or str)  : Address string or bytes
            prefix (bytes or str): Address prefix

        Returns:
            bytes or str: Address string or bytes with prefix removed

        Raises:
            ValueError: If the prefix is not valid
        """
        prefix_got = addr[:len(prefix)]
        if prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected {prefix!r}, got {prefix_got!r})")
        return addr[len(prefix):]

    @staticmethod
    def ValidateLength(addr: Union[bytes, str],
                       len_exp: int) -> None:
        """
        Validate address length.

        Args:
            addr (bytes or str): Address string or bytes
            len_exp (int)      : Expected address length

        Raises:
            ValueError: If the length is not valid
        """
        if len(addr) != len_exp:
            raise ValueError(f"Invalid length (expected {len_exp}, got {len(addr)})")

    @staticmethod
    def ValidatePubKey(pub_key_bytes: bytes,
                       pub_key_cls: Type[IPublicKey]) -> None:
        """
        Validate address length.

        Args:
            pub_key_bytes (bytes)   : Public key bytes
            pub_key_cls (IPublicKey): Public key class type

        Raises:
            ValueError: If the public key is not valid
        """
        if not pub_key_cls.IsValidBytes(pub_key_bytes):
            raise ValueError(f"Invalid {pub_key_cls.CurveType()} public key {BytesUtils.ToHexString(pub_key_bytes)}")

    @staticmethod
    def ValidateChecksum(payload: BytesOrStr,
                         checksum_exp: BytesOrStr,
                         checksum_fct: Callable[[BytesOrStr], BytesOrStr]) -> None:
        """
        Validate address checksum.

        Args:
            payload (bytes or str)     : Payload string or bytes
            checksum_exp (bytes or str): Expected checksum string or bytes
            checksum_fct (function)    : Function for computing checksum

        Raises:
            ValueError: If the computed checksum is not equal to the specified one
        """
        checksum_got = checksum_fct(payload)
        if checksum_exp != checksum_got:
            if isinstance(checksum_exp, bytes) and isinstance(checksum_got, bytes):
                raise ValueError(f"Invalid checksum (expected {BytesUtils.ToHexString(checksum_exp)}, "
                                 f"got {BytesUtils.ToHexString(checksum_got)})")
            raise ValueError(f"Invalid checksum (expected {checksum_exp}, got {checksum_got})")

    @staticmethod
    def SplitPartsByChecksum(addr: BytesOrStr,
                             checksum_len: int,
                             checksum_pos: ChecksumPositions = ChecksumPositions.END) -> Tuple[BytesOrStr, BytesOrStr]:
        """
        Split address in two parts, payload and checksum.

        Args:
            addr (bytes or str)       : Address string or bytes
            checksum_len (int)        : Checksum length
            checksum_pos (bool): True if checksum is at the end of the address, false if it is at the beginning

        Returns:
            tuple[bytes or str, bytes or str]: Payload (index 0) and checksum (index 1)
        """
        checksum = addr[-1 * checksum_len:] if checksum_pos == ChecksumPositions.END else addr[:checksum_len]
        payload = addr[:-1 * checksum_len] if checksum_pos == ChecksumPositions.END else addr[checksum_len:]
        return payload, checksum
