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
Helper library for ed25519 point encoding/decoding, which cannot be done with pynacl APIs.
Encode/Decode operations copied from: https://github.com/warner/python-pure25519/blob/master/pure25519/basic.py
"""
import binascii
from typing import Tuple, Union

from nacl import bindings

from bip_utils.utils.misc import BytesUtils, IntegerUtils


_Q = 2 ** 255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_G = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
      46316835694926478169428394003475163141307993866256225615783033603165251855960)
_G_DEC_BYTES = binascii.unhexlify("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921"
                                  "5866666666666666666666666666666666666666666666666666666666666666")
_G_ENC_BYTES = binascii.unhexlify("5866666666666666666666666666666666666666666666666666666666666666")
_COORD_BYTE_LEN = 32


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


_D = -121665 * _inv(121666)
_I = pow(2, (_Q - 1) // 4, _Q)  # noqa: E741


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


def int_decode(int_bytes: bytes) -> int:
    """
    Decode int from bytes.

    Args:
        int_bytes (bytes): Integer bytes

    Returns:
        int: Decoded integer
    """
    return BytesUtils.ToInteger(int_bytes, endianness="little")


def int_encode(int_val: int) -> bytes:
    """
    Encode int to bytes.

    Args:
        int_val (int): Integer value

    Returns:
        bytes: Encoded integer
    """
    return IntegerUtils.ToBytes(int_val, _COORD_BYTE_LEN, endianness="little")


def point_is_decoded_bytes(point_bytes: bytes) -> bool:
    """
    Get if point bytes are in decoded format.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        bool: True if in decoded format, false otherwise
    """
    return len(point_bytes) == _COORD_BYTE_LEN * 2


def point_is_encoded_bytes(point_bytes: bytes) -> bool:
    """
    Get if point bytes are in encoded format.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        bool: True if in encoded format, false otherwise
    """
    return len(point_bytes) == _COORD_BYTE_LEN


def point_is_valid_bytes(point_bytes: bytes) -> bool:
    """
    Get if point bytes are valid.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        bool: True if valid, false otherwise
    """
    return point_is_decoded_bytes(point_bytes) or point_is_encoded_bytes(point_bytes)


def point_bytes_to_coord(point_bytes: bytes) -> Tuple[int, int]:
    """
    Convert point bytes to coordinates.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        tuple[int, int]: Point coordinates

    Raises:
        ValueError: If point bytes are not valid
    """
    if point_is_decoded_bytes(point_bytes):
        return int_decode(point_bytes[:_COORD_BYTE_LEN]), int_decode(point_bytes[_COORD_BYTE_LEN:])
    if point_is_encoded_bytes(point_bytes):
        return point_decode_no_check(point_bytes)
    raise ValueError("Invalid point bytes")


def point_coord_to_bytes(point_coord: Tuple[int, int]) -> bytes:
    """
    Convert point coordinates to bytes.

    Args:
        point_coord (tuple[int, int]): Point coordinates

    Returns:
        bytes: Point bytes
    """
    return int_encode(point_coord[0]) + int_encode(point_coord[1])


def point_decode_no_check(point_bytes: bytes) -> Tuple[int, int]:
    """
    Decode point bytes to coordinates without checking if it lies on the ed25519 curve.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        tuple[int, int]: Point coordinates

    Raises:
        ValueError: If point bytes are not valid
    """
    if not point_is_encoded_bytes(point_bytes):
        raise ValueError("Invalid point bytes")

    point_int = int_decode(point_bytes)

    clamp = (1 << 255) - 1
    y = point_int & clamp
    x = _x_recover(y)
    if bool(x & 1) != bool(point_int & (1 << 255)):
        x = _Q - x

    return x, y


def point_decode(point_bytes: bytes) -> Tuple[int, int]:
    """
    Decode point bytes to coordinates by checking if it lies on the ed25519 curve.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        tuple[int, int]: Point coordinates

    Raises:
        ValueError: If the point bytes are not valid or the decoded point doesn't lie on the curve
    """
    point_coord = point_decode_no_check(point_bytes)
    if not point_is_on_curve(point_coord):
        raise ValueError("Decoded point does not lie on the curve")
    return point_coord


def point_encode(point_coord: Tuple[int, int]) -> bytes:
    """
    Encode point coordinates to bytes.

    Args:
        point_coord (tuple[int, int]): Point coordinates

    Returns:
        bytes: Point bytes
    """
    point_bytes = point_coord_to_bytes(point_coord)

    y_bytes = bytearray(point_bytes[_COORD_BYTE_LEN:])
    if point_bytes[0] & 1:
        y_bytes[len(y_bytes) - 1] |= 0x80
    return bytes(y_bytes)


def point_is_generator(point: Union[bytes, Tuple[int, int]]) -> bool:
    """
    Get if the point is the generator of the ed25519 curve.

    Args:
        point (bytes or tuple[int, int]): Point

    Returns:
        bool: True if generator, false otherwise

    Raises:
        ValueError: If point bytes are not valid
    """
    # Avoid converting to coordinates if bytes to increase speed
    if isinstance(point, bytes):
        if point_is_encoded_bytes(point):
            return point == _G_ENC_BYTES
        if point_is_decoded_bytes(point):
            return point == _G_DEC_BYTES
        raise ValueError("Invalid point bytes")
    return point == _G


def point_is_on_curve(point: Union[bytes, Tuple[int, int]]) -> bool:
    """
    Get if the point lies on the ed25519 curve.
    This method is used because nacl.bindings.crypto_core_ed25519_is_valid_point performs more strict checks,
    which results in points (i.e. public keys) that are considered not valid even if they are accepted by wallets.

    Args:
        point (bytes or tuple[int, int]): Point

    Returns:
        bool: True if it lies on the curve, false otherwise

    Raises:
        ValueError: If point bytes are not valid
    """
    if isinstance(point, bytes):
        point = point_bytes_to_coord(point)

    x = point[0]
    y = point[1]
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def point_add(point_1: Union[bytes, Tuple[int, int]],
              point_2: Union[bytes, Tuple[int, int]]) -> bytes:
    """
    Add two points on the ed25519 curve.

    Args:
        point_1 (bytes or tuple[int, int]): Point 1
        point_2 (bytes or tuple[int, int]): Point 2

    Returns:
        bytes: New point resulting from the addition
    """
    return bindings.crypto_core_ed25519_add(
        point_1 if isinstance(point_1, bytes) else point_encode(point_1),
        point_2 if isinstance(point_2, bytes) else point_encode(point_2)
    )


def point_scalar_mul(scalar: Union[bytes, int],
                     point: Union[bytes, Tuple[int, int]]) -> bytes:
    """
    Multiply a point on the ed25519 curve with a scalar.

    Args:
        scalar (bytes or int)           : Scalar
        point (bytes or tuple[int, int]): Point

    Returns:
        bytes: New point resulting from the multiplication
    """
    return bindings.crypto_scalarmult_ed25519_noclamp(
        scalar if isinstance(scalar, bytes) else int_encode(scalar),
        point if isinstance(point, bytes) else point_encode(point)
    )


def point_scalar_mul_base(scalar: Union[bytes, int]) -> bytes:
    """
    Multiply the base (i.e. generator) point of the ed25519 curve with a scalar.

    Args:
        scalar (bytes or int): Scalar

    Returns:
        bytes: New point resulting from the multiplication
    """
    return bindings.crypto_scalarmult_ed25519_base_noclamp(
        scalar if isinstance(scalar, bytes) else int_encode(scalar)
    )


def scalar_reduce(scalar: Union[bytes, int]) -> bytes:
    """
    Convert the specified bytes to integer and return its lowest 32-bytes modulo ed25519 curve order.

    Args:
        scalar (bytes or int): Scalar

    Returns:
        bytes: Lowest 32-bytes modulo ed25519-order
    """
    if isinstance(scalar, int):
        scalar = int_encode(scalar)
    return bindings.crypto_core_ed25519_scalar_reduce(
        scalar.ljust(_COORD_BYTE_LEN * 2, b"\x00")
    )


def scalar_is_valid(scalar: Union[bytes, int]) -> bool:
    """
    Get if the specified scalar is valid (i.e. less than the ed25519 curve order).

    Args:
        scalar (bytes or int): Scalar

    Returns:
        bool: True if lower, false otherwise
    """
    if isinstance(scalar, bytes):
        scalar = int_decode(scalar)
    return scalar < _L
