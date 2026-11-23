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

"""Module for nist256p1 point."""

# Imports
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typing_extensions import override

from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ecdsa.ecdsa_keys import EcdsaKeysConst
from bip_utils.ecc.nist256p1.lib import nist256p1_lib
from bip_utils.utils.misc import DataBytes


class Nist256p1Point(IPoint):
    """
    Nist256p1 point class.
    In cryptography library, points are represented by public keys and there are no point functions
    (e.g. add, multiply). For this reason, a public key is used as underlying object and the point
    functions are implemented by nist256p1_lib.
    """

    m_point: ec.EllipticCurvePublicKey

    @override
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
            return cls(nist256p1_lib.point_from_bytes(point_bytes))
        except ValueError as ex:
            raise ValueError("Invalid point bytes") from ex

    @override
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
            return cls(nist256p1_lib.point_from_coord((x, y)))
        except ValueError as ex:
            raise ValueError("Invalid point coordinates") from ex

    def __init__(self,
                 point_obj: ec.EllipticCurvePublicKey) -> None:
        """
        Construct class from point object.

        Args:
            point_obj (ec.EllipticCurvePublicKey): Point object
        """
        self.m_point = point_obj

    @override
    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.NIST256P1

    @override
    @staticmethod
    def CoordinateLength() -> int:
        """
        Get the coordinate length.

        Returns:
           int: Coordinate key length
        """
        return EcdsaKeysConst.POINT_COORD_BYTE_LEN

    @override
    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_point

    @override
    def X(self) -> int:
        """
        Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return nist256p1_lib.point_to_coord(self.m_point)[0]

    @override
    def Y(self) -> int:
        """
        Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return nist256p1_lib.point_to_coord(self.m_point)[1]

    @override
    def Raw(self) -> DataBytes:
        """
        Return the point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.RawDecoded()

    @override
    def RawEncoded(self) -> DataBytes:
        """
        Return the encoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_point.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))

    @override
    def RawDecoded(self) -> DataBytes:
        """
        Return the decoded point raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_point.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:])

    @override
    def __add__(self,
                point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object

        Raises:
            ValueError: If the result is the point at infinity
        """
        return self.__class__(nist256p1_lib.point_add(self.m_point, point.UnderlyingObject()))

    @override
    def __radd__(self,
                 point: IPoint) -> IPoint:
        """
        Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object

        Raises:
            ValueError: If the result is the point at infinity
        """
        return self + point

    @override
    def __mul__(self,
                scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object

        Raises:
            ValueError: If the result is the point at infinity
        """
        if nist256p1_lib.point_is_generator(self.m_point):
            return self.__class__(nist256p1_lib.point_scalar_mul_base(scalar))
        return self.__class__(nist256p1_lib.point_scalar_mul(scalar, self.m_point))

    @override
    def __rmul__(self,
                 scalar: int) -> IPoint:
        """
        Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object

        Raises:
            ValueError: If the result is the point at infinity
        """
        return self * scalar
