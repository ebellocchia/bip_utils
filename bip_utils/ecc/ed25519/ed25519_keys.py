# Copyright (c) 2022 Emanuele Bellocchia
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

"""Module for ed25519 keys."""

# Imports
from typing import Any

from nacl import exceptions, signing

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.ed25519_point import Ed25519Point
from bip_utils.ecc.ed25519.lib import ed25519_lib
from bip_utils.utils.misc import BytesUtils, DataBytes


class Ed25519KeysConst:
    """Class container for ed25519 keys constants."""

    # Public key prefix
    PUB_KEY_PREFIX: bytes = b"\x00"
    # Public key length in bytes
    PUB_KEY_BYTE_LEN: int = 32
    # Private key length in bytes
    PRIV_KEY_BYTE_LEN: int = 32


class Ed25519PublicKey(IPublicKey):
    """Ed25519 public key class."""

    m_ver_key: signing.VerifyKey

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

        # Remove the 0x00 prefix if present because nacl requires 32-byte length
        if (len(key_bytes) == Ed25519KeysConst.PUB_KEY_BYTE_LEN + len(Ed25519KeysConst.PUB_KEY_PREFIX)
                and key_bytes[0] == BytesUtils.ToInteger(Ed25519KeysConst.PUB_KEY_PREFIX)):
            key_bytes = key_bytes[1:]

        # nacl doesn't check if the point lies on curve
        if not ed25519_lib.point_is_on_curve(key_bytes):
            raise ValueError("Invalid public key bytes")

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
        return cls.FromBytes(key_point.RawEncoded().ToBytes())

    def __init__(self,
                 key_obj: signing.VerifyKey) -> None:
        """
        Construct class.

        Args:
            key_obj (signing.VerifyKey): Key object
        """
        self.m_ver_key = key_obj

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
        return Ed25519KeysConst.PUB_KEY_BYTE_LEN + len(Ed25519KeysConst.PUB_KEY_PREFIX)

    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return Ed25519PublicKey.CompressedLength()

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
        return Ed25519Point(bytes(self.m_ver_key))


class Ed25519PrivateKey(IPrivateKey):
    """Ed25519 private key class."""

    m_sign_key: signing.SigningKey

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
                 key_obj: signing.SigningKey) -> None:
        """
        Construct class.

        Args:
            key_obj (signing.SigningKey): Key object
        """
        self.m_sign_key = key_obj

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
