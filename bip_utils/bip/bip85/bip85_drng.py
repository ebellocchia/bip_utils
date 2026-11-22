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

"""
Module for BIP85 deterministic random number generator (BIP85-DRNG-SHAKE256).
Reference: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
"""

# Imports
from bip_utils.utils.crypto import Shake256


class Bip85DrngConst:
    """Class container for BIP85 DRNG constants."""

    # Entropy length in bytes
    ENTROPY_BYTE_LEN: int = 64


class Bip85Drng:
    """
    BIP85 DRNG class.
    It implements the BIP85-DRNG-SHAKE256 deterministic random number generator, which is a SHAKE256 stream
    seeded with the 64-byte entropy derived by BIP85.
    """

    m_shake: Shake256

    def __init__(self,
                 entropy_bytes: bytes) -> None:
        """
        Construct class.

        Args:
            entropy_bytes (bytes): Entropy bytes derived by BIP85 (64-byte)

        Raises:
            ValueError: If the entropy length is not valid
        """
        if len(entropy_bytes) != Bip85DrngConst.ENTROPY_BYTE_LEN:
            raise ValueError(f"Invalid entropy length (expected {Bip85DrngConst.ENTROPY_BYTE_LEN}, "
                             f"got {len(entropy_bytes)})")
        self.m_shake = Shake256(entropy_bytes)

    def Read(self,
             length: int) -> bytes:
        """
        Read the next bytes from the generator.

        Args:
            length (int): Number of bytes to read

        Returns:
            bytes: Read bytes
        """
        return self.m_shake.Read(length)
