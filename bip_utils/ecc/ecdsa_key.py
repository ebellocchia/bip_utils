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
from bip_utils.ecc.key_bytes import KeyBytes


class EcdsaPublicPoint:
    """ ECDSA public point class. """

    def __init__(self,
                 point: ecdsa.ellipticcurve.PointJacobi) -> None:
        """ Construct class.

        Args:
            point (ecdsa.ellipticcurve.PointJacobi object): ecdsa.ellipticcurve.PointJacobi object
        """
        self.m_point = point

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
                other: 'EcdsaPublicPoint') -> 'EcdsaPublicPoint':
        """ Add point to another point.

        Args:
            other (EcdsaPublicPoint object): EcdsaPublicPoint object
        """
        return EcdsaPublicPoint(self.m_point + other.m_point)

    def __mul__(self,
                other: int) -> 'EcdsaPublicPoint':
        """ Multiply point by integer.

        Args:
            other (int): integer
        """
        return EcdsaPublicPoint(self.m_point * other)


class EcdsaPublicKey:
    """ ECDSA public key class.
    Method for verifying signatures is missing because not needed.
    """

    def __init__(self,
                 ver_key: ecdsa.VerifyingKey) -> None:
        """ Construct class.

        Args:
            ver_key (ecdsa.VerifyingKey object): ecdsa.VerifyingKey object
        """
        self.m_ver_key = ver_key

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

    def Point(self) -> EcdsaPublicPoint:
        """ Get public key point.

        Returns:
            EcdsaPublicPoint object: EcdsaPublicPoint object
        """
        return EcdsaPublicPoint(self.m_ver_key.pubkey.point)


class EcdsaPrivateKey:
    """ ECDSA private key class.
    Method for signing messages is missing because not needed.
    """

    def __init__(self,
                 sign_key: ecdsa.SigningKey) -> None:
        """ Construct class.

        Args:
            sign_key (ecdsa.SigningKey object): ecdsa.SigningKey object
        """
        self.m_sign_key = sign_key

    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_sign_key.to_string())

    def GetPublicKey(self) -> EcdsaPublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            EcdsaPublicKey object: EcdsaPublicKey object
        """
        return EcdsaPublicKey(self.m_sign_key.get_verifying_key())
