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
from typing import Callable, Tuple
from bip_utils.utils.misc import ConvUtils


class AddrDecUtils:
    """Class container for address decoding utility functions."""

    @staticmethod
    def ValidateAndRemovePrefix(addr: str,
                                prefix: str) -> str:
        """
        Validate and get a ed25519 public key.

        Args:
            addr (str)  : Address string
            prefix (str): Address prefix

        Returns:
            str: Address string with prefix removed

        Raises:
            ValueError: If the prefix is not valid
        """
        prefix_got = addr[:len(prefix)]
        if prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected {prefix}, got {prefix_got}")
        return addr[len(prefix):]

    @staticmethod
    def SplitChecksumAndPubKey(addr_bytes: bytes,
                               checksum_len: int) -> Tuple[bytes, bytes]:
        """
        Split address in the public key and checksum parts.

        Args:
            addr_bytes (bytes): Address bytes
            checksum_len (int): Checksum length

        Returns:
            tuple: public key (or hash) bytes (index 0) and checksum bytes (index 1)
        """
        checksum = addr_bytes[-1 * checksum_len:]
        pub_key_bytes = addr_bytes[:-1 * checksum_len]
        return pub_key_bytes, checksum

    @staticmethod
    def ValidateChecksum(pub_key_bytes: bytes,
                         checksum_bytes: bytes,
                         checksum_fct: Callable[[bytes], bytes]) -> None:
        """
        Validate checksum.

        Args:
            pub_key_bytes (bytes)  : Public key (or hash) bytes
            checksum_bytes (bytes) : Checksum bytes
            checksum_fct (function): Function for computing checksum

        Raises:
            ValueError: If the computed checksum is not equal tot he specified one
        """
        checksum_got = checksum_fct(pub_key_bytes)
        if checksum_bytes != checksum_got:
            raise ValueError(f"Invalid checksum (expected {ConvUtils.BytesToHexString(checksum_bytes)}, "
                             f"got {ConvUtils.BytesToHexString(checksum_got)})")
