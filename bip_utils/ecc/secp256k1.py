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
import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import generator_secp256k1
from ecdsa.ellipticcurve import PointJacobi
from bip_utils.ecc.ecdsa_key import EcdsaPublicPoint, EcdsaPublicKey, EcdsaPrivateKey
from bip_utils.utils import ConvUtils


class Secp256k1Const:
    """ Class container for Secp256k1 constants. """

    # Curve order
    CURVE_ORDER: int = generator_secp256k1.order()


class Secp256k1:
    """ Secp256k1 class.
    It wraps ecdsa library and provides some simple helper methods for using Secp256k1 curve.
    This is not meant to be complete but just the minimum required to abstract the bip library from the specific ECC library.
    """

    @staticmethod
    def CurveOrder() -> int:
        """ Return the curve order.

        Returns:
            int: Curve order
        """
        return Secp256k1Const.CURVE_ORDER

    @staticmethod
    def Generator() -> EcdsaPublicPoint:
        """ Get the elliptic curve generator point.

        Returns:
            EcdsaPublicPoint object: EcdsaPublicPoint object
        """
        return EcdsaPublicPoint(generator_secp256k1)

    @staticmethod
    def PublicKeyFromBytes(data_bytes: bytes) -> EcdsaPublicKey:
        """ Construct a public key from the specified bytes.

        Args:
            data_bytes (bytes): data bytes

        Returns:
            EcdsaPublicKey object: EcdsaPublicKey object

        Raises:
            ValueError: If the provided bytes are not valid
        """
        try:
            return EcdsaPublicKey(ecdsa.VerifyingKey.from_string(data_bytes, curve=SECP256k1))
        except ecdsa.keys.MalformedPointError as ex:
            raise ValueError("Invalid key bytes") from ex

    @staticmethod
    def PublicKeyFromPoint(point: EcdsaPublicPoint) -> EcdsaPublicKey:
        """ Construct a public key from the specified point.

        Args:
            point (EcdsaPublicPoint object): EcdsaPublicPoint object

        Returns:
            EcdsaPublicKey object: EcdsaPublicKey object

        Raises:
            ValueError: If the provided point is not valid
        """
        try:
            return EcdsaPublicKey(ecdsa.VerifyingKey.from_public_point(point.m_point, curve=SECP256k1))
        except ecdsa.keys.MalformedPointError as ex:
            raise ValueError("Invalid key bytes") from ex

    @staticmethod
    def PrivateKeyFromBytes(data_bytes: bytes) -> EcdsaPrivateKey:
        """ Construct a private key from the specified bytes.

        Args:
            data_bytes (bytes): data bytes

        Returns:
            EcdsaPrivateKey object: EcdsaPrivateKey object

        Raises:
            ValueError: If the provided bytes are not valid
        """
        try:
            return EcdsaPrivateKey(ecdsa.SigningKey.from_string(data_bytes, curve=SECP256k1))
        except ecdsa.keys.MalformedPointError as ex:
            raise ValueError("Invalid key bytes") from ex

    @staticmethod
    def IsPublicKeyBytesValid(data_bytes: bytes) -> bool:
        """Get if the specified bytes correspond to a valid public key.

        Args:
            data_bytes (bytes): data bytes

        Returns:
            bool: True if valid, false otherwise
        """
        try:
            Secp256k1.PublicKeyFromBytes(data_bytes)
            return True
        except ValueError:
            return False

    @staticmethod
    def IsPrivateKeyBytesValid(data_bytes: bytes) -> bool:
        """Get if the specified bytes correspond to a valid private key.

        Args:
            data_bytes (bytes): data bytes

        Returns:
            bool: True if valid, false otherwise
        """
        try:
            Secp256k1.PrivateKeyFromBytes(data_bytes)
            return True
        except ValueError:
            return False
