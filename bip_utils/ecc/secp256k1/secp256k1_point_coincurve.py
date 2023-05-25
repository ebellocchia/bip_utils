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

"""Module for secp256k1 point based on coincurve library."""

# Imports
from typing import Any

import coincurve

from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ecdsa.ecdsa_keys import EcdsaKeysConst
from bip_utils.utils.misc import DataBytes, IntegerUtils


class Secp256k1PointCoincurve(IPoint):
    """
    Secp256k1 point class.
    In coincurve library, all the point functions (e.g. add, multiply) are coded inside the
    PublicKey class. For this reason, a PublicKey is used as underlying object.
    """

    m_pub_key: coincurve.PublicKey

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
        if len(point_bytes) == EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN - 1:
            return cls(coincurve.PublicKey(EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_PREFIX + point_bytes))
        if len(point_bytes) == EcdsaKeysConst.PUB_KEY_COMPRESSED_BYTE_LEN:
            return cls(coincurve.PublicKey(point_bytes))
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
            return cls(coincurve.PublicKey.from_point(x, y))
        except ValueError as ex:
            raise ValueError("Invalid point coordinates") from ex

    def __init__(self,
                 point_obj: coincurve.PublicKey) -> None:
        """
        Construct class from point object.

        Args:
            point_obj (coincurve.PublicKey): Point object
        """
        self.m_pub_key = point_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.SECP256K1

    @staticmethod
    def CoordinateLength() -> int:
        """
        Get the coordinate length.

        Returns:
           int: Coordinate key length
        """
        return EcdsaKeysConst.POINT_COORD_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_pub_key

    def X(self) -> int:
        """
        Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_pub_key.point()[0]

    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_pub_key.point()[1]

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
        return DataBytes(self.m_pub_key.format(True))

    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_pub_key.format(False)[1:])

    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return self.__class__(self.m_pub_key.combine([point.UnderlyingObject()]))

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
        return self.__class__(self.m_pub_key.multiply(IntegerUtils.ToBytes(scalar)))

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
