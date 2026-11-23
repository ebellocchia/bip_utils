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
Helper library for nist256p1 keys and points, based on the cryptography library.
The cryptography library represents points as public keys and doesn't provide point arithmetic, so:
- scalar multiplications are performed by OpenSSL (constant-time), via key derivation and ECDH
- point addition is computed here, and it's only applied to public points
"""

# Imports
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from bip_utils.ecc.ecdsa.ecdsa_keys import EcdsaKeysConst
from bip_utils.utils.misc import BytesUtils


_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
_CURVE = ec.SECP256R1()
_PUB_KEY_HYBRID_PREFIXES = (0x06, 0x07)


def _inv(x: int) -> int:
    # pow(x, -1, _P) requires Python 3.8
    return pow(x, _P - 2, _P)


def _y_recover(x: int) -> int:
    # Since _P = 3 (mod 4), the square root of y^2 is (y^2)^((_P + 1) / 4)
    return pow((x * x * x + _A * x + _B) % _P, (_P + 1) // 4, _P)


def _coord_add(point_coord_1: Tuple[int, int],
               point_coord_2: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    # Affine point addition, None is returned for the point at infinity
    (x1, y1), (x2, y2) = point_coord_1, point_coord_2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _ecdh_x(scalar: int,
            point: ec.EllipticCurvePublicKey) -> int:
    # ECDH returns the X coordinate of the point multiplied by the private key
    return BytesUtils.ToInteger(priv_key_from_int(scalar).exchange(ec.ECDH(), point))


def _scalar_reduce(scalar: int) -> int:
    scalar %= _N
    if scalar == 0:
        raise ValueError("Scalar multiplication results in the point at infinity")
    return scalar


def priv_key_from_int(priv_key_int: int) -> ec.EllipticCurvePrivateKey:
    """
    Construct a private key from an integer.

    Args:
        priv_key_int (int): Private key integer

    Returns:
        ec.EllipticCurvePrivateKey: Private key object

    Raises:
        ValueError: If the private key is not valid
    """
    # Check here because old versions of the library don't always raise ValueError for keys out of range
    if not 0 < priv_key_int < _N:
        raise ValueError("Invalid private key")
    return ec.derive_private_key(priv_key_int, _CURVE)


def point_from_bytes(point_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """
    Construct a point from bytes.
    Raw (i.e. X and Y coordinates), compressed, uncompressed and hybrid formats are supported.

    Args:
        point_bytes (bytes): Point bytes

    Returns:
        ec.EllipticCurvePublicKey: Point object

    Raises:
        ValueError: If the point is not valid
    """
    # Raw and hybrid formats are not supported by the library, so convert them to uncompressed format
    if len(point_bytes) == EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN - 1:
        point_bytes = EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_PREFIX + point_bytes
    elif (len(point_bytes) == EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN
          and point_bytes[0] in _PUB_KEY_HYBRID_PREFIXES):
        # The prefix also encodes the parity of the Y coordinate, which shall be consistent
        if (point_bytes[0] & 1) != (point_bytes[-1] & 1):
            raise ValueError("Invalid hybrid point encoding")
        point_bytes = EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_PREFIX + point_bytes[1:]
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, point_bytes)


def point_from_coord(point_coord: Tuple[int, int]) -> ec.EllipticCurvePublicKey:
    """
    Construct a point from coordinates.

    Args:
        point_coord (tuple[int, int]): Point coordinates

    Returns:
        ec.EllipticCurvePublicKey: Point object

    Raises:
        ValueError: If the point is not valid
    """
    x, y = point_coord
    # Check here because recent versions of OpenSSL accept coordinates greater than the field prime
    if not (0 <= x < _P and 0 <= y < _P):
        raise ValueError("Invalid point coordinates")
    return ec.EllipticCurvePublicNumbers(x, y, _CURVE).public_key()


def point_to_coord(point: ec.EllipticCurvePublicKey) -> Tuple[int, int]:
    """
    Get point coordinates.

    Args:
        point (ec.EllipticCurvePublicKey): Point object

    Returns:
        tuple[int, int]: Point coordinates
    """
    point_nums = point.public_numbers()
    return point_nums.x, point_nums.y


def point_is_generator(point: ec.EllipticCurvePublicKey) -> bool:
    """
    Get if the point is the generator of the nist256p1 curve.

    Args:
        point (ec.EllipticCurvePublicKey): Point object

    Returns:
        bool: True if generator, false otherwise
    """
    return point_to_coord(point) == _G


def point_add(point_1: ec.EllipticCurvePublicKey,
              point_2: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """
    Add two points on the nist256p1 curve.
    The addition is not constant-time, so it shall not be applied to secret points.

    Args:
        point_1 (ec.EllipticCurvePublicKey): Point 1 object
        point_2 (ec.EllipticCurvePublicKey): Point 2 object

    Returns:
        ec.EllipticCurvePublicKey: New point resulting from the addition

    Raises:
        ValueError: If the result is the point at infinity
    """
    point_coord = _coord_add(point_to_coord(point_1), point_to_coord(point_2))
    if point_coord is None:
        raise ValueError("Point addition results in the point at infinity")
    return point_from_coord(point_coord)


def point_scalar_mul(scalar: int,
                     point: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """
    Multiply a point on the nist256p1 curve with a scalar.
    The multiplications by the scalar are performed by OpenSSL via ECDH, which only returns the X coordinate.
    The Y coordinate is then recovered using the X coordinate of the next multiple, i.e. (scalar + 1) * point.

    Args:
        scalar (int)                     : Scalar
        point (ec.EllipticCurvePublicKey): Point object

    Returns:
        ec.EllipticCurvePublicKey: New point resulting from the multiplication

    Raises:
        ValueError: If the result is the point at infinity
    """
    scalar = _scalar_reduce(scalar)
    point_coord = point_to_coord(point)
    # (n - 1) * point is the opposite point, handled here because n * point is the point at infinity
    if scalar == _N - 1:
        return point_from_coord((point_coord[0], _P - point_coord[1]))

    # The Y coordinate is one of the two square roots, the right one is such that:
    # (x, y) + point = (scalar + 1) * point
    x = _ecdh_x(scalar, point)
    y = _y_recover(x)
    x_next = _ecdh_x(scalar + 1, point)
    point_coord_next = _coord_add((x, y), point_coord)
    if point_coord_next is None or point_coord_next[0] != x_next:
        y = _P - y
    return point_from_coord((x, y))


def point_scalar_mul_base(scalar: int) -> ec.EllipticCurvePublicKey:
    """
    Multiply the base (i.e. generator) point of the nist256p1 curve with a scalar.

    Args:
        scalar (int): Scalar

    Returns:
        ec.EllipticCurvePublicKey: New point resulting from the multiplication

    Raises:
        ValueError: If the result is the point at infinity
    """
    return priv_key_from_int(_scalar_reduce(scalar)).public_key()
