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

"""Module for nist256p1 keys."""

# Imports
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typing_extensions import override

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ecdsa.ecdsa_keys import EcdsaKeysConst
from bip_utils.ecc.nist256p1.lib import nist256p1_lib
from bip_utils.ecc.nist256p1.nist256p1_point import Nist256p1Point
from bip_utils.utils.misc import BytesUtils, DataBytes, IntegerUtils


class Nist256p1PublicKey(IPublicKey):
    """Nist256p1 public key class."""

    m_ver_key: ec.EllipticCurvePublicKey

    @override
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
        try:
            return cls(nist256p1_lib.point_from_bytes(key_bytes))
        except ValueError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @override
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
        try:
            return cls(nist256p1_lib.point_from_coord((key_point.X(), key_point.Y())))
        except ValueError as ex:
            raise ValueError("Invalid public key point") from ex

    def __init__(self,
                 key_obj: ec.EllipticCurvePublicKey) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (ec.EllipticCurvePublicKey): Key object
        """
        self.m_ver_key = key_obj

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
    def CompressedLength() -> int:
        """
        Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return EcdsaKeysConst.PUB_KEY_COMPRESSED_BYTE_LEN

    @override
    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return EcdsaKeysConst.PUB_KEY_UNCOMPRESSED_BYTE_LEN

    @override
    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_ver_key

    @override
    def RawCompressed(self) -> DataBytes:
        """
        Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_ver_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))

    @override
    def RawUncompressed(self) -> DataBytes:
        """
        Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_ver_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))

    @override
    def Point(self) -> IPoint:
        """
        Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Nist256p1Point(self.m_ver_key)


class Nist256p1PrivateKey(IPrivateKey):
    """Nist256p1 private key class."""

    m_sign_key: ec.EllipticCurvePrivateKey

    @override
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
        # Check here because the library takes the key as an integer
        if len(key_bytes) != cls.Length():
            raise ValueError("Invalid private key bytes")
        try:
            return cls(nist256p1_lib.priv_key_from_int(BytesUtils.ToInteger(key_bytes)))
        except ValueError as ex:
            raise ValueError("Invalid private key bytes") from ex

    def __init__(self,
                 key_obj: ec.EllipticCurvePrivateKey) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (ec.EllipticCurvePrivateKey): Key object
        """
        self.m_sign_key = key_obj

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
    def Length() -> int:
        """
        Get the key length.

        Returns:
           int: Key length
        """
        return EcdsaKeysConst.PRIV_KEY_BYTE_LEN

    @override
    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key

    @override
    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(
            IntegerUtils.ToBytes(self.m_sign_key.private_numbers().private_value, bytes_num=self.Length())
        )

    @override
    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Nist256p1PublicKey(self.m_sign_key.public_key())
