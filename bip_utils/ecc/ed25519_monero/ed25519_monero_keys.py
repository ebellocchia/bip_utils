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

"""Module for ed25519-monero keys."""

# Imports
from nacl import signing

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.common.ipoint import IPoint
from bip_utils.ecc.curve.elliptic_curve_types import EllipticCurveTypes
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519KeysConst, Ed25519PrivateKey, Ed25519PublicKey
from bip_utils.ecc.ed25519.lib import ed25519_lib
from bip_utils.ecc.ed25519_monero.ed25519_monero_point import Ed25519MoneroPoint
from bip_utils.utils.misc import DataBytes


class Ed25519MoneroPublicKey(Ed25519PublicKey):
    """Ed25519-Monero public key class."""

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_MONERO

    @staticmethod
    def CompressedLength() -> int:
        """
        Get the compressed key length.

        Returns:
           int: Compressed key length
        """
        return Ed25519KeysConst.PUB_KEY_BYTE_LEN

    @staticmethod
    def UncompressedLength() -> int:
        """
        Get the uncompressed key length.

        Returns:
           int: Uncompressed key length
        """
        return Ed25519MoneroPublicKey.CompressedLength()

    def RawCompressed(self) -> DataBytes:
        """
        Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return DataBytes(bytes(self.m_ver_key))

    def Point(self) -> IPoint:
        """
        Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return Ed25519MoneroPoint(bytes(self.m_ver_key))


class Ed25519MoneroPrivateKey(Ed25519PrivateKey):
    """Ed25519-Monero private key class."""

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
        if not ed25519_lib.scalar_is_valid(key_bytes):
            raise ValueError("Invalid private key bytes")
        return super().FromBytes(key_bytes)

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Get the elliptic curve type.

        Returns:
           EllipticCurveTypes: Elliptic curve type
        """
        return EllipticCurveTypes.ED25519_MONERO

    def PublicKey(self) -> IPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return Ed25519MoneroPublicKey(
            signing.VerifyKey(
                ed25519_lib.point_scalar_mul_base(bytes(self.m_sign_key))
            )
        )
