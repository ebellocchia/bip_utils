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

"""Module for ed25519 point."""

# Imports
from typing import Any
from ecpy.curves import Curve, ECPyException, Point
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.utils.misc import BytesUtils, DataBytes, IntegerUtils


class Ed25519PointConst:
    """Class container for ed25519 point constants."""

    # Point coordinte length in bytes
    POINT_COORD_BYTE_LEN: int = 32


class Ed25519Point(IPoint):
    """Ed25519 point class."""

    m_point: Point

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
        try:
            if len(point_bytes) == Ed25519PointConst.POINT_COORD_BYTE_LEN:
                return cls(Curve.get_curve("Ed25519").decode_point(point_bytes))
            if len(point_bytes) == Ed25519PointConst.POINT_COORD_BYTE_LEN * 2:
                return cls(
                    Point(
                        cls.__DecodeInt(point_bytes[:Ed25519PointConst.POINT_COORD_BYTE_LEN]),
                        cls.__DecodeInt(point_bytes[Ed25519PointConst.POINT_COORD_BYTE_LEN:]),
                        Curve.get_curve("Ed25519")
                    )
                )
        except ECPyException as ex:
            raise ValueError("Invalid point bytes") from ex
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
        try:
            return cls(Point(x, y, Curve.get_curve("Ed25519")))
        except ECPyException as ex:
            raise ValueError("Invalid point key coordinates") from ex

    def __init__(self,
                 point_obj: Any) -> None:
        """
        Construct class from point object.

        Args:
            point_obj (class): Point object

        Raises:
            TypeError: If point object is not of the correct type
        """
        if not isinstance(point_obj, Point):
            raise TypeError("Invalid point object type")
        self.m_point = point_obj

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
        return self.m_point.x

    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_point.y

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
        return DataBytes(Curve.get_curve("Ed25519").encode_point(self.m_point))

    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.__EncodeInt(self.m_point.x) + self.__EncodeInt(self.m_point.y))

    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return Ed25519Point(self.m_point + point.UnderlyingObject())

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
        return Ed25519Point(self.m_point * scalar)

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

    @staticmethod
    def __DecodeInt(int_bytes: bytes) -> int:
        """
        Decode bytes to integer.

        Args:
            int_bytes (bytes): Integer bytes

        Returns:
            int: Decoded integer
        """
        return BytesUtils.ToInteger(int_bytes, endianness="little")

    @staticmethod
    def __EncodeInt(int_val: int) -> bytes:
        """
        Encode integer to bytes.

        Args:
            int_val (int): Integer value

        Returns:
            bytes: Encoded integer
        """
        return IntegerUtils.ToBytes(int_val, Ed25519PointConst.POINT_COORD_BYTE_LEN, endianness="little")
