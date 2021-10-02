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

# Secp256k1 curve based on coincurve library

# Imports
import coincurve
from typing import Any
from bip_utils.ecc.dummy_point import DummyPoint
from bip_utils.ecc.ecdsa_keys import EcdsaKeysConst
from bip_utils.ecc.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ikeys import IPoint, IPublicKey, IPrivateKey
from bip_utils.utils import ConvUtils, DataBytes


class Secp256k1Point(IPoint):
    """ Secp256k1 point class.
    In coincurve library, all the point functions (e..g add, multiply) are coded inside the
    PublicKey class. For this reason, a PublicKey is used as underlying object.
    """

    @classmethod
    def FromBytes(cls,
                  point_bytes: bytes) -> IPoint:
        """ Construct class from point bytes.

        Args:
            point_bytes (bytes): Point bytes

        Returns:
            IPoint: IPoint object
        """
        if len(point_bytes) != EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN - 1:
            raise ValueError("Invalid point bytes")

        return cls(coincurve.PublicKey(EcdsaKeysConst.PUB_KEY_COMPRESSED_PREFIX + point_bytes))

    @classmethod
    def FromCoordinates(cls,
                        x: int,
                        y: int) -> IPoint:
        """ Construct class from point coordinates.

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
                 point_obj: Any) -> None:
        """ Construct class from point object.

        Args:
            point_obj (class): Point object

        Raises:
            TypeError: If point object is not of the correct type
        """
        if not isinstance(point_obj, coincurve.PublicKey):
            raise TypeError("Invalid point object type")
        self.m_pub_key = point_obj

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_pub_key

    def X(self) -> int:
        """ Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_pub_key.point()[0]

    def Y(self) -> int:
        """ Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_pub_key.point()[1]

    def Raw(self) -> DataBytes:
        """ Return the point encoded to raw bytes.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_pub_key.format(False)[1:])

    def __add__(self,
                point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return Secp256k1Point(self.m_pub_key.combine([point.UnderlyingObject()]))

    def __radd__(self,
                 point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        return self + point

    def __mul__(self,
                scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        return Secp256k1Point(self.m_pub_key.multiply(ConvUtils.IntegerToBytes(scalar)))

    def __rmul__(self,
                 scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        return self * scalar


class Secp256k1PublicKey(IPublicKey):
    """ Secp256k1 public key class. """

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPublicKey:
        """ Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key bytes are not valid
        """
        try:
            return cls(coincurve.PublicKey(key_bytes))
        except ValueError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def FromPoint(cls,
                  key_point: IPoint) -> IPublicKey:
        """ Construct class from key point.

        Args:
            key_point (IPoint object): Key point

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key point is not valid
        """
        try:
            return cls(
                coincurve.PublicKey.from_point(key_point.X(),
                                               key_point.Y())
                )
        except ValueError as ex:
            raise ValueError("Invalid public key point") from ex

    def __init__(self,
                 key_obj: Any) -> None:
        """ Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
        """
        if not isinstance(key_obj, coincurve.PublicKey):
            raise TypeError("Invalid public key object type")
        self.m_ver_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """ Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.SECP256K1

    @staticmethod
    def CompressedLength() -> int:
        """ Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return EcdsaKeysConst.PUB_KEY_COMPRESSED_BYTE_LEN

    @staticmethod
    def UncompressedLength() -> int:
        """ Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_ver_key

    def RawCompressed(self) -> DataBytes:
        """ Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_ver_key.format(True))

    def RawUncompressed(self) -> DataBytes:
        """ Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_ver_key.format(False))

    def Point(self) -> IPoint:
        """ Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        point = self.m_ver_key.point()
        return Secp256k1Point.FromCoordinates(point[0], point[1])


class Secp256k1PrivateKey(IPrivateKey):
    """ Secp256k1 private key class. """

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPrivateKey:
        """ Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey: IPrivateKey object

        Raises:
            ValueError: If key bytes are not valid
        """
        # Check here because the library does not raise any exception
        if len(key_bytes) != cls.Length():
            raise ValueError("Invalid private key bytes")

        try:
            return cls(coincurve.PrivateKey(key_bytes))
        except ValueError as ex:
            raise ValueError("Invalid private key bytes") from ex

    def __init__(self,
                 key_obj: Any) -> None:
        """ Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
        """
        if not isinstance(key_obj, coincurve.PrivateKey):
            raise TypeError("Invalid private key object type")
        self.m_sign_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """ Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.SECP256K1

    @staticmethod
    def Length() -> int:
        """ Get the key length.

        Returns:
           int: Key length
        """
        return EcdsaKeysConst.PRIV_KEY_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key

    def Raw(self) -> DataBytes:
        """ Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_sign_key.secret)

    def PublicKey(self) -> IPublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Secp256k1PublicKey(self.m_sign_key.public_key)
