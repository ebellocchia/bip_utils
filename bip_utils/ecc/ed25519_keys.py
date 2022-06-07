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

"""Module for ed25519 keys handling."""

# Imports
from typing import Any
from ecpy.curves import Curve, ECPyException, Point
from nacl import exceptions, signing
from bip_utils.ecc.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ikeys import IPoint, IPublicKey, IPrivateKey
from bip_utils.utils.misc import BytesUtils, DataBytes, IntegerUtils


class Ed25519KeysConst:
    """Class container for ed25519 keys constants."""

    # Point length in bytes
    POINT_BYTE_LEN: int = 32
    # Public key prefix
    PUB_KEY_PREFIX: bytes = b"\x00"
    # Compressed public key length in bytes
    PUB_KEY_COMPRESSED_BYTE_LEN: int = 33
    # Uncompressed public key length in bytes
    PUB_KEY_UNCOMPRESSED_BYTE_LEN: int = 33
    # Private key length in bytes
    PRIV_KEY_BYTE_LEN: int = 32


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
            cv = Curve.get_curve("Ed25519")
            return cls(cv.decode_point(point_bytes))
        except ECPyException as ex:
            raise ValueError("Invalid point key bytes") from ex

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
        x_bytes = IntegerUtils.ToBytes(self.m_point.x, Ed25519KeysConst.POINT_BYTE_LEN)
        y_bytes = IntegerUtils.ToBytes(self.m_point.y, Ed25519KeysConst.POINT_BYTE_LEN)

        return DataBytes(x_bytes + y_bytes)

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


class Ed25519PublicKey(IPublicKey):
    """Ed25519 public key class."""

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPublicKey:
        """
        Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key bytes are not valid
        """

        # Remove the prefix if present because nacl requires 32-byte length
        if (len(key_bytes) == cls.CompressedLength()
                and key_bytes[0] == BytesUtils.ToInteger(Ed25519KeysConst.PUB_KEY_PREFIX)):
            key_bytes = key_bytes[1:]

        # nacl doesn't check if the point lies on curve
        try:
            Curve.get_curve("Ed25519").decode_point(key_bytes)
        except AssertionError as ex:
            raise ValueError("Invalid public key bytes") from ex

        try:
            return cls(signing.VerifyKey(key_bytes))
        except (exceptions.RuntimeError, exceptions.ValueError) as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def FromPoint(cls,
                  key_point: IPoint) -> IPublicKey:
        """
        Construct class from key point.

        Args:
            key_point (IPoint object): Key point

        Returns:
            IPublicKey: IPublicKey object

        Raises:
            ValueError: If key point is not valid
        """
        cv = Curve.get_curve("Ed25519")
        return cls.FromBytes(cv.encode_point(key_point.UnderlyingObject()))

    def __init__(self,
                 key_obj: Any) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
        """
        if isinstance(key_obj, signing.VerifyKey):
            self.m_ver_key = key_obj
        else:
            raise TypeError("Invalid public key object type")

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519

    @staticmethod
    def CompressedLength() -> int:
        """
        Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return Ed25519KeysConst.PUB_KEY_COMPRESSED_BYTE_LEN

    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return Ed25519KeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_ver_key

    def RawCompressed(self) -> DataBytes:
        """
        Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(Ed25519KeysConst.PUB_KEY_PREFIX + bytes(self.m_ver_key))

    def RawUncompressed(self) -> DataBytes:
        """
        Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """

        # Same as compressed
        return self.RawCompressed()

    def Point(self) -> IPoint:
        """
        Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Ed25519Point.FromBytes(bytes(self.m_ver_key))


class Ed25519PrivateKey(IPrivateKey):
    """Ed25519 private key class."""

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> IPrivateKey:
        """
        Construct class from key bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey: IPrivateKey object

        Raises:
            ValueError: If key bytes are not valid
        """
        try:
            return cls(signing.SigningKey(key_bytes))
        except (exceptions.RuntimeError, exceptions.ValueError) as ex:
            raise ValueError("Invalid private key bytes") from ex

    def __init__(self,
                 key_obj: Any) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
        """
        if isinstance(key_obj, signing.SigningKey):
            self.m_sign_key = key_obj
        else:
            raise TypeError("Invalid private key object type")

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519

    @staticmethod
    def Length() -> int:
        """
        Get the key length.

        Returns:
           int: Key length
        """
        return Ed25519KeysConst.PRIV_KEY_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key

    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(bytes(self.m_sign_key))

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Ed25519PublicKey(self.m_sign_key.verify_key)
