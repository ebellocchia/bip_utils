# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module for SHA-3 algorithms."""

# Imports
import hashlib
from typing import Any, Union

from Crypto.Hash import SHA3_256, SHAKE256, keccak

from bip_utils.utils.misc import AlgoUtils


HASHLIB_USE_SHA3_256: bool = "sha3_256" in hashlib.algorithms_available


class Kekkak256:
    """
    Kekkak-256 class.
    It computes digests using Kekkak-256 algorithm.
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
        return keccak.new(data=AlgoUtils.Encode(data), digest_bits=256).digest()

    @staticmethod
    def DigestSize() -> int:
        """
        Get the digest size in bytes.

        Returns:
            int: Digest size in bytes
        """
        return (hashlib.new("sha3_256").digest_size
                if HASHLIB_USE_SHA3_256
                else keccak.new(digest_bits=256).digest_size)


class Sha3_256:     # noqa: N801
    """
    SHA3-256 class.
    It computes digests using SHA3-256 algorithm.
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
        if HASHLIB_USE_SHA3_256:
            return hashlib.new("sha3_256", AlgoUtils.Encode(data)).digest()
        # Use Cryptodome if not implemented in hashlib
        return SHA3_256.new(AlgoUtils.Encode(data)).digest()

    @staticmethod
    def DigestSize() -> int:
        """
        Get the digest size in bytes.

        Returns:
            int: Digest size in bytes
        """
        return (hashlib.new("sha3_256").digest_size
                if HASHLIB_USE_SHA3_256
                else SHA3_256.digest_size)


class Shake256:
    """
    SHAKE256 class.
    It computes variable-length digests using the SHAKE256 extendable-output function.
    The output can be read incrementally, like a stream.
    """

    handle: Any

    def __init__(self,
                 data: Union[bytes, str] = b"") -> None:
        """
        Construct class.

        Args:
            data (str or bytes, optional): Initial data (default: empty)
        """
        self.handle = SHAKE256.new(AlgoUtils.Encode(data))

    def Update(self,
               data: Union[bytes, str]) -> None:
        """
        Update digest.
        It cannot be called anymore after reading the output.

        Args:
            data (str or bytes): Data

        Raises:
            TypeError: If called after reading the output
        """
        self.handle.update(AlgoUtils.Encode(data))

    def Read(self,
             length: int) -> bytes:
        """
        Read the next bytes of the output.

        Args:
            length (int): Number of bytes to read

        Returns:
            bytes: Output bytes
        """
        return self.handle.read(length)

    @staticmethod
    def QuickDigest(data: Union[bytes, str],
                    digest_len: int) -> bytes:
        """
        Compute the digest (quick version).

        Args:
            data (str or bytes): Data
            digest_len (int)   : Digest length in bytes

        Returns:
            bytes: Computed digest
        """
        return SHAKE256.new(AlgoUtils.Encode(data)).read(digest_len)
