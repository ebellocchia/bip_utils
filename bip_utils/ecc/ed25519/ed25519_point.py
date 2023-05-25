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

"""Module for ed25519 point."""

# Imports
from typing import Any, Optional

from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.lib import ed25519_lib
from bip_utils.utils.misc import DataBytes


class Ed25519PointConst:
    """Class container for ed25519 point constants."""

    # Point coordinate length in bytes
    POINT_COORD_BYTE_LEN: int = 32


class Ed25519Point(IPoint):
    """Ed25519 point class."""

    m_is_generator: bool
    m_enc_bytes: bytes
    m_x: Optional[int]
    m_y: Optional[int]

    @classmethod
    def FromBytes(cls,
                  point_bytes: bytes) -> IPoint:
        """
        Construct class from point bytes.

        Args:
            point_bytes (bytes): Point bytes

        Returns:
            IPoint: IPoint object
        """
        if not ed25519_lib.point_is_on_curve(point_bytes):
            raise ValueError("Invalid point bytes")
        if ed25519_lib.point_is_decoded_bytes(point_bytes):
            point_bytes = ed25519_lib.point_encode(
                ed25519_lib.point_bytes_to_coord(point_bytes)
            )
        return cls(point_bytes)

    @classmethod
    def FromCoordinates(cls,
                        x: int,
                        y: int) -> IPoint:
        """
        Construct class from point coordinates.

        Args:
            x (int): X coordinate of the point
            y (int): Y coordinate of the point

        Returns:
            IPoint: IPoint object
        """
        return cls.FromBytes(
            ed25519_lib.point_coord_to_bytes((x, y))
        )

    def __init__(self,
                 point_bytes: bytes) -> None:
        """
        Construct class from point object.

        Args:
            point_bytes (bytes): Point bytes
        """
        if not ed25519_lib.point_is_encoded_bytes(point_bytes):
            raise ValueError("Invalid point bytes")

        self.m_enc_bytes = point_bytes
        self.m_is_generator = ed25519_lib.point_is_generator(point_bytes)
        self.m_x, self.m_y = None, None

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519

    @staticmethod
    def CoordinateLength() -> int:
        """
        Get the coordinate length.

        Returns:
           int: Coordinate key length
        """
        return Ed25519PointConst.POINT_COORD_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_enc_bytes

    def X(self) -> int:
        """
        Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        if self.m_x is None:
            self.m_x, self.m_y = ed25519_lib.point_bytes_to_coord(self.m_enc_bytes)
        return self.m_x

    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        if self.m_y is None:
            self.m_x, self.m_y = ed25519_lib.point_bytes_to_coord(self.m_enc_bytes)
        return self.m_y

    def Raw(self) -> DataBytes:
        """
        Return the point encoded to raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.RawDecoded()

    def RawEncoded(self) -> DataBytes:
        """
        Return the encoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_enc_bytes)

    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(ed25519_lib.int_encode(self.X()) + ed25519_lib.int_encode(self.Y()))

    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return self.__class__(
            ed25519_lib.point_add(self.m_enc_bytes, point.UnderlyingObject())
        )

    def __radd__(self,
                 point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return self + point

    def __mul__(self,
                scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        if self.m_is_generator:
            return self.__class__(
                ed25519_lib.point_scalar_mul_base(scalar)
            )
        return self.__class__(
            ed25519_lib.point_scalar_mul(scalar, self.m_enc_bytes)
        )

    def __rmul__(self,
                 scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        return self * scalar
