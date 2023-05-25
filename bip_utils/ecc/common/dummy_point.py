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

"""Module with helper class for representing a dummy point."""

# Imports
from typing import Any

from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.utils.misc import DataBytes


class DummyPointConst:
    """Class container for dummy point constants."""

    # Point coordinate length in bytes
    POINT_COORD_BYTE_LEN: int = 32


class DummyPoint(IPoint):
    """Dummy point class."""

    m_x: int
    m_y: int

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
        return cls((x, y))

    def __init__(self,
                 point_obj: Any) -> None:
        """
        Construct class from point object.

        Args:
            point_obj (class): Point object

        Raises:
            TypeError: If point object is not of the correct type
        """
        if (not isinstance(point_obj, tuple)
                or len(point_obj) != 2
                or not isinstance(point_obj[0], int)
                or not isinstance(point_obj[1], int)):
            raise TypeError("Invalid point object type")
        self.m_x = point_obj[0]
        self.m_y = point_obj[1]

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """

    @staticmethod
    def CoordinateLength() -> int:
        """
        Get the coordinate length.

        Returns:
           int: Coordinate key length
        """
        return DummyPointConst.POINT_COORD_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """

    def X(self) -> int:
        """
        Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_x

    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_y

    def Raw(self) -> DataBytes:
        """
        Return the point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """

    def RawEncoded(self) -> DataBytes:
        """
        Return the encoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """

    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """

    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """

    def __radd__(self,
                 point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """

    def __mul__(self,
                scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """

    def __rmul__(self,
                 scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
