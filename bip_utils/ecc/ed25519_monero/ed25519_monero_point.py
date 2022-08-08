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

"""Module for ed25519-monero point."""

# Imports
from typing import Any, Tuple

from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519_monero.lib import ed25519_monero_lib
from bip_utils.utils.misc import DataBytes


class Ed25519MoneroPointConst:
    """Class container for Ed25519-Monero point constants."""

    # Point coordinate length in bytes
    POINT_COORD_BYTE_LEN: int = 32


class Ed25519MoneroPoint(IPoint):
    """Ed25519-Monero point class."""

    m_point: Tuple[int, int, int, int]

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
        if len(point_bytes) == Ed25519MoneroPointConst.POINT_COORD_BYTE_LEN:
            return cls(ed25519_monero_lib.decodepoint(point_bytes))
        if len(point_bytes) == Ed25519MoneroPointConst.POINT_COORD_BYTE_LEN * 2:
            return cls(ed25519_monero_lib.decodepointxy(
                ed25519_monero_lib.decodeint(point_bytes[:Ed25519MoneroPointConst.POINT_COORD_BYTE_LEN]),
                ed25519_monero_lib.decodeint(point_bytes[Ed25519MoneroPointConst.POINT_COORD_BYTE_LEN:]))
            )
        raise ValueError("Invalid point bytes")

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
        return cls(ed25519_monero_lib.decodepointxy(x, y))

    def __init__(self,
                 point_obj: Tuple[int, int, int, int]) -> None:
        """
        Construct class from point object.

        Args:
            point_obj (tuple): Point object
        """
        self.m_point = point_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_MONERO

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_point

    def X(self) -> int:
        """
        Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_point[0]

    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_point[1]

    def Raw(self) -> DataBytes:
        """
        Return the point raw bytes.

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
        return DataBytes(ed25519_monero_lib.encodepoint(self.m_point))

    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(
            ed25519_monero_lib.encodeint(self.X()) + ed25519_monero_lib.encodeint(self.Y())
        )

    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return self.__class__(ed25519_monero_lib.edwards_add(self.m_point, point.UnderlyingObject()))

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

        # Use scalarmult_B for generator point, which is more efficient
        if ed25519_monero_lib.is_generator_point(self.m_point):
            return self.__class__(ed25519_monero_lib.scalarmult_B(scalar))
        return self.__class__(ed25519_monero_lib.scalarmult(self.m_point, scalar))

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
