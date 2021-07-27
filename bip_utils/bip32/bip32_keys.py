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
from functools import lru_cache
from typing import Union
from bip_utils.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip32.bip32_key_ser import Bip32PrivateKeySerializer, Bip32PublicKeySerializer
from bip_utils.bip32.bip32_key_data import Bip32FingerPrint, Bip32KeyData
from bip_utils.ecc import EllipticCurveGetter, EllipticCurveTypes, IPoint, IPrivateKey, IPublicKey
from bip_utils.utils import CryptoUtils, DataBytes


class Bip32PublicKey:
    """ BIP32 public key class.
    It represents a public key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
    """

    @classmethod
    def FromBytesOrKeyObject(cls,
                             pub_key: Union[bytes, IPublicKey],
                             key_data: Bip32KeyData,
                             curve_type: EllipticCurveTypes) -> Bip32PublicKey:
        """ Get the public key from key bytes or object.

        Args:
            pub_key (bytes or IPublicKey)  : Public key
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Returns:
            Bip32PublicKey object: Bip32PublicKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(pub_key, key_data, curve_type)
                if isinstance(pub_key, bytes)
                else cls(pub_key, key_data))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes,
                  key_data: Bip32KeyData,
                  curve_type: EllipticCurveTypes) -> Bip32PublicKey:
        """ Create from bytes.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes, curve_type),
                   key_data)

    def __init__(self,
                 pub_key: IPublicKey,
                 key_data: Bip32KeyData) -> None:
        """ Construct class.

        Args:
            pub_key (IPublicKey object)   : Key object
            key_data (Bip32KeyData object): Key data
        """
        self.m_pub_key = pub_key
        self.m_key_data = key_data

    def CurveType(self) -> EllipticCurveTypes:
        """ Return key elliptic curve type.

        Returns:
            EllipticCurveTypes: Elliptic curve type
        """
        return self.m_pub_key.CurveType()

    def KeyObject(self) -> IPublicKey:
        """ Return the key object.

        Returns:
            IPublicKey object: Key object
        """
        return self.m_pub_key

    def Data(self) -> Bip32KeyData:
        """ Return key data.

        Returns:
            BipKeyData object: BipKeyData object
        """
        return self.m_key_data

    @lru_cache()
    def RawCompressed(self) -> DataBytes:
        """ Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawCompressed()

    @lru_cache()
    def RawUncompressed(self) -> DataBytes:
        """ Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawUncompressed()

    def Point(self) -> IPoint:
        """ Get public key point.

        Returns:
            IPoint object: IPoint object
        """
        return self.m_pub_key.Point()

    @lru_cache()
    def FingerPrint(self) -> Bip32FingerPrint:
        """ Get key fingerprint.

        Returns:
            bytes: Key fingerprint bytes
        """
        return Bip32FingerPrint(self.KeyIdentifier())

    @lru_cache()
    def KeyIdentifier(self) -> bytes:
        """ Get key identifier.

        Returns:
            bytes: Key identifier bytes
        """
        return CryptoUtils.Hash160(self.m_pub_key.RawCompressed().ToBytes())

    @lru_cache()
    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return Bip32PublicKeySerializer.Serialize(self.m_pub_key,
                                                  self.m_key_data)

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
            return curve.PublicKeyClass().FromBytes(key_bytes)
        except ValueError as ex:
            raise Bip32KeyError("Invalid public key") from ex


class Bip32PrivateKey:
    """ BIP32 private key class.
    It represents a private key used by BIP32 with all the related data (e.g. depth, chain code, etc...).
    """

    @classmethod
    def FromBytesOrKeyObject(cls,
                             priv_key: Union[bytes, IPrivateKey],
                             key_data: Bip32KeyData,
                             curve_type: EllipticCurveTypes) -> Bip32PrivateKey:
        """ Get the public key from key bytes or object.

        Args:
            priv_key (bytes or IPrivateKey): Private key
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(priv_key, key_data, curve_type)
                if isinstance(priv_key, bytes)
                else cls(priv_key, key_data))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes,
                  key_data: Bip32KeyData,
                  curve_type: EllipticCurveTypes) -> Bip32PrivateKey:
        """ Create from bytes.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes, curve_type),
                   key_data)

    def __init__(self,
                 priv_key: IPrivateKey,
                 key_data: Bip32KeyData) -> None:
        """ Construct class.

        Args:
            priv_key (IPrivateKey object) : Key object
            key_data (Bip32KeyData object): Key data
        """
        self.m_priv_key = priv_key
        self.m_key_data = key_data

    def CurveType(self) -> EllipticCurveTypes:
        """ Return key elliptic curve type.

        Returns:
            EllipticCurveTypes: Elliptic curve type
        """
        return self.m_priv_key.CurveType()

    def KeyObject(self) -> IPrivateKey:
        """ Return the key object.

        Returns:
            IPrivateKey object: Key object
        """
        return self.m_priv_key

    def Data(self) -> Bip32KeyData:
        """ Return key data.

        Returns:
            BipKeyData object: BipKeyData object
        """
        return self.m_key_data

    @lru_cache()
    def Raw(self) -> DataBytes:
        """ Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_priv_key.Raw()

    @lru_cache()
    def PublicKey(self) -> Bip32PublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return Bip32PublicKey(self.m_priv_key.PublicKey(),
                              self.m_key_data)

    @lru_cache()
    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        return Bip32PrivateKeySerializer.Serialize(self.m_priv_key,
                                                   self.m_key_data)

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
            return curve.PrivateKeyClass().FromBytes(key_bytes)
        except ValueError as ex:
            raise Bip32KeyError("Invalid private key") from ex
