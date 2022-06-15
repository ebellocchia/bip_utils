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

"""Tiny wrapper for pynacl point arithmetic."""

from typing import Union
from nacl import bindings
from bip_utils.ecc.ed25519.lib.ed25519_lib import encode_int, point_is_encoded, point_encode


def point_add(point_1: bytes,
              point_2: bytes) -> bytes:
    """
    Add two points on the ed25519 curve.

    Args:
        point_1 (bytes): Point 1 bytes
        point_2 (bytes): Point 2 bytes

    Returns:
        bytes: New point resulting from the addition
    """
    return bindings.crypto_core_ed25519_add(
        point_1 if point_is_encoded(point_1) else point_encode(point_1),
        point_2 if point_is_encoded(point_2) else point_encode(point_2)
    )


def point_mul(scalar: Union[bytes, int],
              point: bytes) -> bytes:
    """
    Multiply a point on the ed25519 curve with a scalar.

    Args:
        scalar (int) : Scalar
        point (bytes): Point bytes

    Returns:
        bytes: New point resulting from the multiplication
    """
    return bindings.crypto_scalarmult_ed25519_noclamp(
        scalar if isinstance(scalar, bytes) else encode_int(scalar),
        point if point_is_encoded(point) else point_encode(point)
    )


def point_mul_base(scalar: Union[bytes, int]) -> bytes:
    """
    Multiply the base point of the ed25519 curve with a scalar.

    Args:
        scalar (int) : Scalar

    Returns:
        bytes: New point resulting from the multiplication
    """
    return bindings.crypto_scalarmult_ed25519_base_noclamp(
        scalar if isinstance(scalar, bytes) else encode_int(scalar),
    )
