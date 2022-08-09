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
Small helper library for ed25519 point encoding/decoding, which cannot be done with pynacl APIs.
Encode/Decode operations copied from: https://github.com/warner/python-pure25519/blob/master/pure25519/basic.py
"""

from typing import Tuple, Union

from bip_utils.utils.misc import BytesUtils, IntegerUtils


Q = 2 ** 255 - 19


def _inv(x: int) -> int:
    return pow(x, Q - 2, Q)


d = -121665 * _inv(121666)
I = pow(2, (Q - 1) // 4, Q)  # noqa: E741


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


def decode_int(int_bytes: bytes) -> int:
    return BytesUtils.ToInteger(int_bytes, endianness="little")


def encode_int(int_val: int) -> bytes:
    return IntegerUtils.ToBytes(int_val, 32, endianness="little")


def point_is_decoded(p: bytes) -> bool:
    return len(p) == 64


def point_is_encoded(p: bytes) -> bool:
    return len(p) == 32


# nacl.bindings.crypto_core_ed25519_is_valid_point performs more strict checks
# This results in points (i.e. public keys) that are considered not valid even if they are accepted by wallets
# For this reason, this function is used instead
def point_is_on_curve(p: Tuple[int, int]) -> bool:
    x = p[0]
    y = p[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % Q == 0


def point_decode_no_check(unclamped: Union[bytes, int]) -> Tuple[int, int]:
    if isinstance(unclamped, bytes):
        unclamped = decode_int(unclamped)

    clamp = (1 << 255) - 1
    y = unclamped & clamp  # clear MSB
    x = _x_recover(y)
    if bool(x & 1) != bool(unclamped & (1 << 255)):
        x = Q - x
    return x, y


def point_decode(unclamped: Union[bytes, int]) -> Tuple[int, int]:
    p = point_decode_no_check(unclamped)
    if not point_is_on_curve(p):
        raise ValueError("decoding point that is not on curve")
    return p


def point_encode(p: bytes) -> bytes:
    if not point_is_decoded(p):
        raise ValueError("Invalid point")

    y_bytes = bytearray(p[32:])
    if p[0] & 1:
        y_bytes[len(y_bytes) - 1] |= 0x80
    return bytes(y_bytes)


def point_bytes_to_coord(p: bytes) -> Tuple[int, int]:
    if not point_is_decoded(p):
        raise ValueError("Invalid point")
    return decode_int(p[:32]), decode_int(p[32:])


def point_coord_to_bytes(p: Tuple[int, int]) -> bytes:
    return encode_int(p[0]) + encode_int(p[1])
