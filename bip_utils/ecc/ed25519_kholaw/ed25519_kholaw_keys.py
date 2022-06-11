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
With respect to ed25519, the private key has a length of 64-byte (32-byte of the ed25519 private key and a 32-byte
additional part).
For computing the public key, the ed25519 private key (32-byte leftmost part) shall be considered a 32-byte
little endian integer and multiplied by the ed25519 curve generator point.
"""

# Imports
from typing import Any
from bip_utils.ecc.common.ikeys import IPublicKey, IPrivateKey
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.ed25519_const import Ed25519Const
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PublicKey, Ed25519PrivateKey
from bip_utils.utils.misc import BytesUtils, DataBytes


class Ed25519KholawKeysConst:
    """Class container for ed25519-kholaw keys constants."""

    # Private key length in bytes
    PRIV_KEY_BYTE_LEN: int = 64


class Ed25519KholawPublicKey(Ed25519PublicKey):
    """Ed25519-Kholaw public key class."""


class Ed25519KholawPrivateKey(IPrivateKey):
    """Ed25519-Kholaw private extended key class."""

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
        if (len(key_bytes) != Ed25519KholawKeysConst.PRIV_KEY_BYTE_LEN
                or not Ed25519PrivateKey.IsValidBytes(key_bytes[:Ed25519PrivateKey.Length()])):
            raise ValueError("Invalid private key bytes")
        return cls(key_bytes)

    def __init__(self,
                 key_obj: Any) -> None:
        """
        Construct class from key object.

        Args:
            key_obj (class): Key object

        Raises:
            TypeError: If key object is not of the correct type
        """
        if isinstance(key_obj, bytes):
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
        return self.m_sign_key

    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(self.m_sign_key)

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        priv_key_int = BytesUtils.ToInteger(self.m_sign_key[:Ed25519PrivateKey.Length()],
                                            endianness="little")
        return Ed25519KholawPublicKey.FromPoint(priv_key_int * Ed25519Const.GENERATOR)
