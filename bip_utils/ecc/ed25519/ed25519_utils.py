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

"""Module for ed25519 utility functions."""

# Imports
from typing import Union

from bip_utils.ecc.ed25519.lib import ed25519_lib


class Ed25519Utils:
    """Class container for ed25519 utility functions."""

    @staticmethod
    def IntDecode(int_bytes: bytes) -> int:
        """
        Decode int from bytes.

        Args:
            int_bytes (bytes): Integer bytes

        Returns:
            int: Decoded integer
        """
        return ed25519_lib.int_decode(int_bytes)

    @staticmethod
    def IntEncode(int_val: int) -> bytes:
        """
        Encode int to bytes.

        Args:
            int_val (int): Integer value

        Returns:
            bytes: Encoded integer
        """
        return ed25519_lib.int_encode(int_val)

    @staticmethod
    def ScalarReduce(scalar: Union[bytes, int]) -> bytes:
        """
        Convert the specified bytes to integer and return its lowest 32-bytes modulo ed25519-order.

        Args:
            scalar (bytes or int): Scalar

        Returns:
            bytes: Lowest 32-bytes modulo ed25519-order
        """
        return ed25519_lib.scalar_reduce(scalar)
