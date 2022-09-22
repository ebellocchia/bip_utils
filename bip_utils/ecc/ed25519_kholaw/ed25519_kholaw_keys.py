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

"""
Module for ed25519-kholaw keys.
With respect to ed25519, the private key has a length of 64-byte (left 32-byte of the ed25519 private key and a
right 32-byte extension part).
"""

# Imports
from typing import Any

from nacl import signing

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PrivateKey, Ed25519PublicKey
from bip_utils.ecc.ed25519.lib import ed25519_lib
from bip_utils.ecc.ed25519_kholaw.ed25519_kholaw_point import Ed25519KholawPoint
from bip_utils.utils.misc import DataBytes


class Ed25519KholawKeysConst:
    """Class container for ed25519-kholaw keys constants."""

    # Private key length in bytes
    PRIV_KEY_BYTE_LEN: int = 64


class Ed25519KholawPublicKey(Ed25519PublicKey):
    """Ed25519-Kholaw public key class."""

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_KHOLAW

    def Point(self) -> IPoint:
        """
        Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Ed25519KholawPoint(bytes(self.m_ver_key))


class Ed25519KholawPrivateKey(IPrivateKey):
    """Ed25519-Kholaw private key class."""

    m_sign_key: Ed25519PrivateKey
    m_ext_key: bytes

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
        return cls(Ed25519PrivateKey.FromBytes(key_bytes[:Ed25519PrivateKey.Length()]),
                   key_bytes[Ed25519PrivateKey.Length():])

    def __init__(self,
                 key_obj: IPrivateKey,
                 key_ex_bytes: bytes) -> None:
        """
        Construct class.

        Args:
            key_obj (IPrivateKey object): Key object, shall be an Ed25519PrivateKey private key
            key_ex_bytes (bytes)        : Key extended bytes

        Raises:
            TypeError: If key object is not of the correct type
            ValueError: If extended key is not valid
        """
        if not isinstance(key_obj, Ed25519PrivateKey):
            raise TypeError("Invalid private key object type")
        if len(key_ex_bytes) != Ed25519PrivateKey.Length():
            raise ValueError("Invalid extended key length")

        self.m_sign_key = key_obj
        self.m_ext_key = key_ex_bytes

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_KHOLAW

    @staticmethod
    def Length() -> int:
        """
        Get the key length.

        Returns:
           int: Key length
        """
        return Ed25519KholawKeysConst.PRIV_KEY_BYTE_LEN

    def UnderlyingObject(self) -> Any:
        """
        Get the underlying object.

        Returns:
           Any: Underlying object
        """
        return self.m_sign_key.UnderlyingObject()

    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_sign_key.Raw().ToBytes() + self.m_ext_key)

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Ed25519KholawPublicKey(
            signing.VerifyKey(
                ed25519_lib.point_scalar_mul_base(bytes(self.m_sign_key.UnderlyingObject()))
            )
        )
