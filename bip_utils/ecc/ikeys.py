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
from abc import ABC, abstractmethod
from typing import Any, Optional, Union
from bip_utils.ecc.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.key_bytes import KeyBytes


class IPoint(ABC):
    """ Interface for a generic elliptic curve point. """

    @abstractmethod
    def __init__(self,
                 x: int,
                 y: int,
                 order: Optional[int]) -> None:
        """ Construct class from point coordinates.

        Args:
            x (int): X coordinate
            y (int): Y coordinate
            order (int): Order
        """
        pass

    @staticmethod
    @abstractmethod
    def CurveType() -> EllipticCurveTypes:
        """ Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        pass

    @abstractmethod
    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        pass

    @abstractmethod
    def Order(self) -> int:
        """ Return the point order.

        Returns:
            int: Point order
        """
        pass

    @abstractmethod
    def X(self) -> int:
        """ Return X coordinate of the point.

        Returns:
            int: X coordinate of the point
        """
        pass

    @abstractmethod
    def Y(self) -> int:
        """ Return Y coordinate of the point.

        Returns:
            int: Y coordinate of the point
        """
        pass

    @abstractmethod
    def __add__(self,
                point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        pass

    @abstractmethod
    def __radd__(self,
                 point: IPoint) -> IPoint:
        """ Add point to another point.

        Args:
            point (IPoint object): IPoint object

        Returns:
            IPoint object: IPoint object
        """
        pass

    @abstractmethod
    def __mul__(self,
                scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        pass

    @abstractmethod
    def __rmul__(self,
                 scalar: int) -> IPoint:
        """ Multiply point by a scalar.

        Args:
            scalar (int): scalar

        Returns:
            IPoint object: IPoint object
        """
        pass


class IPublicKey(ABC):
    """ Interface for a generic elliptic curve public key.
    Verify method is missing because not needed.
    """

    @abstractmethod
    def __init__(self,
                 key_data: Union[bytes, IPoint]) -> None:
        """ Construct class from key bytes or point and curve.

        Args:
            key_data (bytes or IPoint object): key bytes or point

        Raises:
            ValueError: If key data is not valid
        """
        pass

    @staticmethod
    @abstractmethod
    def CurveType() -> EllipticCurveTypes:
        """ Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        pass

    @staticmethod
    @abstractmethod
    def IsValid(key_data: Union[bytes, IPoint]) -> bool:
        """ Return if the specified data represents a valid public key.

        Args:
            key_data (bytes or IPoint object): key bytes or point

        Returns:
            bool: True if valid, false otherwise
        """
        pass

    @staticmethod
    @abstractmethod
    def CompressedLength() -> int:
        """ Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        pass

    @staticmethod
    @abstractmethod
    def UncompressedLength() -> int:
        """ Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        pass

    @abstractmethod
    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        pass

    @abstractmethod
    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def Point(self) -> IPoint:
        """ Return the public key point.

        Returns:
            IPoint object: IPoint object
        """
        pass


class IPrivateKey(ABC):
    """ Interface for a generic elliptic curve private key.
    Sign method is missing because not needed.
    """

    @abstractmethod
    def __init__(self,
                 key_bytes: bytes) -> None:
        """ Construct class from key bytes and curve.

        Args:
            key_bytes (bytes): key bytes

        Raises:
            ValueError: If key bytes are not valid
        """
        pass

    @staticmethod
    @abstractmethod
    def CurveType() -> EllipticCurveTypes:
        """ Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        pass

    @staticmethod
    @abstractmethod
    def IsValid(key_bytes: bytes) -> bool:
        """ Return if the specified bytes represent a valid private key.

        Args:
            key_bytes (bytes): key bytes

        Returns:
            bool: True if valid, false otherwise
        """
        pass

    @staticmethod
    @abstractmethod
    def Length() -> int:
        """ Get the key length.

        Returns:
           int: Key length
        """
        pass

    @abstractmethod
    def UnderlyingObject(self) -> Any:
        """ Get the underlying object.

        Returns:
           Any: Underlying object
        """
        pass

    @abstractmethod
    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def PublicKey(self) -> IPublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        pass
