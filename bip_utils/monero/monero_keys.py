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

"""Module for Monero keys handling."""

# Imports
from __future__ import annotations

from functools import lru_cache
from typing import Union

from bip_utils.ecc import Ed25519MoneroPrivateKey, Ed25519MoneroPublicKey, IPoint, IPrivateKey, IPublicKey
from bip_utils.monero.monero_ex import MoneroKeyError
from bip_utils.utils.misc import DataBytes


class MoneroPublicKey:
    """Monero public key class."""

    m_pub_key: IPublicKey

    @classmethod
    def FromBytesOrKeyObject(cls,
                             pub_key: Union[bytes, IPublicKey]) -> MoneroPublicKey:
        """
        Get the public key from key bytes or object.

        Args:
            pub_key (bytes or IPublicKey): Public key

        Returns:
            MoneroPublicKey object: MoneroPublicKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(pub_key)
                if isinstance(pub_key, bytes)
                else cls(pub_key))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> MoneroPublicKey:
        """
        Create from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            MoneroPublicKey object: MoneroPublicKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes))

    @classmethod
    def FromPoint(cls,
                  key_point: IPoint) -> MoneroPublicKey:
        """
        Create from point.

        Args:
            key_point (IPoint object): Key point

        Returns:
            MoneroPublicKey object: MoneroPublicKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromPoint(key_point))

    def __init__(self,
                 pub_key: IPublicKey) -> None:
        """
        Construct class.

        Args:
            pub_key (IPublicKey object): Key object

        Raises:
            MoneroKeyError: If the bytes length is not valid
            TypeError: If the key is not a Ed25519MoneroPublicKey object
        """
        if not isinstance(pub_key, Ed25519MoneroPublicKey):
            raise TypeError("Invalid public key object type")
        self.m_pub_key = pub_key

    def KeyObject(self) -> IPublicKey:
        """
        Return the key object.

        Returns:
            IPublicKey object: Key object
        """
        return self.m_pub_key

    @lru_cache()
    def RawCompressed(self) -> DataBytes:
        """
        Return raw compressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawCompressed()

    @lru_cache()
    def RawUncompressed(self) -> DataBytes:
        """
        Return raw uncompressed public key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_pub_key.RawUncompressed()

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes) -> IPublicKey:
        """
        Construct key from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Ed25519MoneroPublicKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise MoneroKeyError("Invalid public key") from ex

    @staticmethod
    def __KeyFromPoint(key_point: IPoint) -> IPublicKey:
        """
        Construct key from point.

        Args:
            key_point (IPoint object): Key point

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Ed25519MoneroPublicKey.FromPoint(key_point)
        except ValueError as ex:
            raise MoneroKeyError("Invalid key point") from ex


class MoneroPrivateKey:
    """Monero private key class."""

    m_priv_key: IPrivateKey

    @classmethod
    def FromBytesOrKeyObject(cls,
                             priv_key: Union[bytes, IPrivateKey]) -> MoneroPrivateKey:
        """
        Get the private key from key bytes or object.

        Args:
            priv_key (bytes or IPrivateKey): Private key

        Returns:
            MoneroPrivateKey object: MoneroPrivateKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(priv_key)
                if isinstance(priv_key, bytes)
                else cls(priv_key))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> MoneroPrivateKey:
        """
        Create from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes))

    def __init__(self,
                 priv_key: IPrivateKey) -> None:
        """
        Construct class.

        Args:
            priv_key (IPrivateKey object): Key object

        Raises:
            MoneroKeyError: If the bytes length is not valid
            TypeError: If the key is not a Ed25519MoneroPrivateKey object
        """
        if not isinstance(priv_key, Ed25519MoneroPrivateKey):
            raise TypeError("Invalid private key object type")
        self.m_priv_key = priv_key

    def KeyObject(self) -> IPrivateKey:
        """
        Return the key object.

        Returns:
            IPrivateKey object: Key object
        """
        return self.m_priv_key

    @lru_cache()
    def Raw(self) -> DataBytes:
        """
        Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_priv_key.Raw()

    @lru_cache()
    def PublicKey(self) -> MoneroPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            MoneroPublicKey object: MoneroPublicKey object
        """
        return MoneroPublicKey(self.m_priv_key.PublicKey())

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes) -> IPrivateKey:
        """
        Construct key from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Ed25519MoneroPrivateKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise MoneroKeyError("Invalid private key") from ex
