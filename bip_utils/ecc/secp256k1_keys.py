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


# Imports
from __future__ import annotations
from typing import Any, Union
import ecdsa
from ecdsa import curves, ellipticcurve, keys
from ecdsa.ecdsa import curve_secp256k1
from bip_utils.ecc.ikeys import IPoint, IPublicKey, IPrivateKey
from bip_utils.ecc.key_bytes import KeyBytes


class Secp256k1Point(IPoint):
    """ Secp256k1 point class. """

    def __init__(self,
                 x: int,
                 y: int) -> None:
        """ Construct class from point coordinates.

        Args:
            x (int): X coordinate
            y (int): Y coordinate
        """
        self.m_point = ellipticcurve.PointJacobi.from_affine(ellipticcurve.Point(curve_secp256k1, x, y))

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_point

    def X(self) -> int:
        """ Get point X coordinate.

        Returns:
           int: Point X coordinate
        """
        return self.m_point.x()

    def Y(self) -> int:
        """ Get point Y coordinate.

        Returns:
           int: Point Y coordinate
        """
        return self.m_point.y()

    def __add__(self,
                point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        new_point = (self.m_point + point.UnderlyingObject()).to_affine()
        return Secp256k1Point(new_point.x(), new_point.y())

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
        new_point = (self.m_point * scalar).to_affine()
        return Secp256k1Point(new_point.x(), new_point.y())

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

    def __init__(self,
                 key_data: Union[bytes, IPoint]) -> None:
        """ Construct class from key bytes or point and curve.

        Args:
            key_data (bytes or IPoint object): key bytes or point

        Raises:
            ValueError: If key data is not valid
        """
        if isinstance(key_data, bytes):
            self.m_ver_key = self.__FromBytes(key_data)
        elif isinstance(key_data, Secp256k1Point):
            self.m_ver_key = self.__FromPoint(key_data)
        else:
            raise TypeError("Invalid public key data type")

    @staticmethod
    def IsValid(key_data: Union[bytes, IPoint]) -> bool:
        """ Return if the specified data represents a valid public key.

        Args:
            key_data (bytes or IPoint object): key bytes or point

        Returns:
            bool: True if valid, false otherwise
        """
        try:
            Secp256k1PublicKey(key_data)
            return True
        except ValueError:
            return False

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_ver_key

    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_ver_key.to_string("compressed"))

    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_ver_key.to_string("uncompressed"))

    def Point(self) -> IPoint:
        """ Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Secp256k1Point(self.m_ver_key.pubkey.point.x(), self.m_ver_key.pubkey.point.y())

    @staticmethod
    def __FromBytes(key_bytes: bytes) -> ecdsa.VerifyingKey:
        """ Get public key from bytes.

        Args:
            key_bytes (bytes): key bytes

        Returns:
            ecdsa.VerifyingKey: ecdsa.VerifyingKey object
        """
        try:
            return ecdsa.VerifyingKey.from_string(key_bytes,
                                                  curve=curves.SECP256k1)
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @staticmethod
    def __FromPoint(point: IPoint) -> ecdsa.VerifyingKey:
        """ Get public key from point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            ecdsa.VerifyingKey: ecdsa.VerifyingKey object
        """
        try:
            return ecdsa.VerifyingKey.from_public_point(ellipticcurve.Point(curve_secp256k1, point.X(), point.Y()),
                                                        curve=curves.SECP256k1)
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key point") from ex


class Secp256k1PrivateKey(IPrivateKey):
    """ Secp256k1 private key class. """

    def __init__(self,
                 key_bytes: bytes) -> None:
        """ Construct class from key bytes and curve.

        Args:
            key_bytes (bytes): key bytes

        Raises:
            ValueError: If key bytes are not valid
        """
        try:
            self.m_sign_key = ecdsa.SigningKey.from_string(key_bytes, curve=curves.SECP256k1)
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid private key bytes") from ex

    @staticmethod
    def IsValid(key_bytes: bytes) -> bool:
        """ Return if the specified bytes represent a valid private key.

        Args:
            key_bytes (bytes): key bytes

        Returns:
            bool: True if valid, false otherwise
        """
        try:
            Secp256k1PrivateKey(key_bytes)
            return True
        except ValueError:
            return False

    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key

    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_sign_key.to_string())

    def PublicKey(self) -> Secp256k1PublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            Secp256k1PublicKey object: Secp256k1PublicKey object
        """
        return Secp256k1PublicKey(self.m_sign_key.get_verifying_key().to_string("uncompressed"))
