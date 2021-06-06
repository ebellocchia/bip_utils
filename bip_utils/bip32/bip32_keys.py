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
from bip_utils.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip32.bip32_key_ser import Bip32PrivateKeySerializer, Bip32PublicKeySerializer
from bip_utils.bip32.bip32_key_data import Bip32FingerPrint, Bip32KeyData
from bip_utils.ecc import EllipticCurveGetter, EllipticCurveTypes, KeyBytes, IPoint, IPrivateKey, IPublicKey
from bip_utils.utils import CryptoUtils


class Bip32PublicKey:
    """ BIP32 public key class.
    It represents a public key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
    """

    def __init__(self,
                 key_bytes: bytes,
                 key_data: Bip32KeyData,
                 curve_type: EllipticCurveTypes) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        self.m_pub_key = self.__KeyFromBytes(key_bytes, curve_type)
        self.m_key_data = key_data
        # Pre-compute serialized key and key identifier
        self.m_ser_key = Bip32PublicKeySerializer.Serialize(self.m_pub_key,
                                                            key_data)
        self.m_key_ident = CryptoUtils.Hash160(self.m_pub_key.RawCompressed().ToBytes())

    def CurveType(self) -> EllipticCurveTypes:
        """ Return key elliptic curve type.

        Returns:
            EllipticCurveTypes: Elliptic curve type
        """
        return self.m_pub_key.CurveType()

    def Data(self) -> Bip32KeyData:
        """ Return key data.

        Returns:
            BipKeyData object: BipKeyData object
        """
        return self.m_key_data

    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_pub_key.RawCompressed()

    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_pub_key.RawUncompressed()

    def Point(self) -> IPoint:
        """ Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return self.m_pub_key.Point()

    def FingerPrint(self) -> Bip32FingerPrint:
        """ Get key fingerprint.

        Returns:
            bytes: Key fingerprint bytes
        """
        return Bip32FingerPrint(self.KeyIdentifier())

    def KeyIdentifier(self) -> bytes:
        """ Get key identifier.

        Returns:
            bytes: Key identifier bytes
        """
        return self.m_key_ident

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_ser_key

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes,
                       curve_type: EllipticCurveTypes) -> IPublicKey:
        """ Construct key from bytes.

        Args:
            key_bytes (bytes)              : Key bytes
            curve_type (EllipticCurveTypes): Elliptic curve type

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        try:
            curve = EllipticCurveGetter.FromType(curve_type)
            return curve.PublicKeyClass()(key_bytes)
        except ValueError as ex:
            raise Bip32KeyError("Invalid public key") from ex


class Bip32PrivateKey:
    """ BIP32 private key class.
    It represents a private key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
    """

    def __init__(self,
                 key_bytes: bytes,
                 key_data: Bip32KeyData,
                 curve_type: EllipticCurveTypes) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        self.m_priv_key = self.__KeyFromBytes(key_bytes, curve_type)
        self.m_key_data = key_data
        self.m_pub_key = Bip32PublicKey(self.m_priv_key.PublicKey().RawCompressed().ToBytes(),
                                        key_data,
                                        curve_type)
        # Pre-compute serialized key
        self.m_ser_key = Bip32PrivateKeySerializer.Serialize(self.m_priv_key, key_data)

    def CurveType(self) -> EllipticCurveTypes:
        """ Return key elliptic curve type.

        Returns:
            EllipticCurveTypes: Elliptic curve type
        """
        return self.m_priv_key.CurveType()

    def Data(self) -> Bip32KeyData:
        """ Return key data.

        Returns:
            BipKeyData object: BipKeyData object
        """
        return self.m_key_data

    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return self.m_priv_key.Raw()

    def PublicKey(self) -> Bip32PublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            BipPublicKey object: BipPublicKey object
        """
        return self.m_pub_key

    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return self.m_ser_key

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes,
                       curve_type: EllipticCurveTypes) -> IPrivateKey:
        """ Construct key from bytes.

        Args:
            key_bytes (bytes)              : Key bytes
            curve_type (EllipticCurveTypes): Elliptic curve type

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        try:
            curve = EllipticCurveGetter.FromType(curve_type)
            return curve.PrivateKeyClass()(key_bytes)
        except ValueError as ex:
            raise Bip32KeyError("Invalid private key") from ex
