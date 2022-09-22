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

"""Module for ed25519-blake2b keys."""

# Imports
from typing import Any

import ed25519_blake2b

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519KeysConst, Ed25519PublicKey
from bip_utils.ecc.ed25519.lib import ed25519_lib
from bip_utils.ecc.ed25519_blake2b.ed25519_blake2b_point import Ed25519Blake2bPoint
from bip_utils.utils.misc import BytesUtils, DataBytes


class Ed25519Blake2bPublicKey(IPublicKey):
    """Ed25519-Blake2b public key class."""

    m_ver_key: ed25519_blake2b.VerifyingKey

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

        # Remove the 0x00 prefix if present
        if (len(key_bytes) == Ed25519KeysConst.PUB_KEY_BYTE_LEN + len(Ed25519KeysConst.PUB_KEY_PREFIX)
                and key_bytes[0] == BytesUtils.ToInteger(Ed25519KeysConst.PUB_KEY_PREFIX)):
            key_bytes = key_bytes[1:]
        # The library does not raise any exception in case of length error
        elif len(key_bytes) != Ed25519KeysConst.PUB_KEY_BYTE_LEN:
            raise ValueError("Invalid public key bytes")

        # The library doesn't check if the point lies on curve
        if not ed25519_lib.point_is_on_curve(key_bytes):
            raise ValueError("Invalid public key bytes")

        return cls(ed25519_blake2b.VerifyingKey(key_bytes))

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
                 key_obj: ed25519_blake2b.VerifyingKey) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (ed25519_blake2b.VerifyingKey): Key object
        """
        self.m_ver_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_BLAKE2B

    @staticmethod
    def CompressedLength() -> int:
        """
        Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return Ed25519PublicKey.CompressedLength()

    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return Ed25519PublicKey.UncompressedLength()

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
        return DataBytes(Ed25519KeysConst.PUB_KEY_PREFIX + self.m_ver_key.to_bytes())

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
        return Ed25519Blake2bPoint(self.m_ver_key.to_bytes())


class Ed25519Blake2bPrivateKey(IPrivateKey):
    """Ed25519-Blake2b private key class."""

    m_sign_key: ed25519_blake2b.SigningKey

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
            return cls(ed25519_blake2b.SigningKey(key_bytes))
        except ValueError as ex:
            raise ValueError("Invalid private key bytes") from ex

    def __init__(self,
                 key_obj: ed25519_blake2b.SigningKey) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (ed25519_blake2b.SigningKey): Key object
        """
        self.m_sign_key = key_obj

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_BLAKE2B

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
        return DataBytes(self.m_sign_key.to_bytes())

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Ed25519Blake2bPublicKey(self.m_sign_key.get_verifying_key())
