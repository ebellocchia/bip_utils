# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module for TON keys handling."""

# Imports
from __future__ import annotations

from functools import lru_cache
from typing import Union

from bip_utils.ecc import IPrivateKey, IPublicKey
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PrivateKey, Ed25519PublicKey
from bip_utils.ton.ton_ex import TonKeyError
from bip_utils.utils.misc import DataBytes


class TonPublicKey:
    """TON public key class."""

    m_pub_key: IPublicKey

    @classmethod
    def FromBytesOrKeyObject(cls,
                             pub_key: Union[bytes, IPublicKey]) -> TonPublicKey:
        """
        Get the public key from key bytes or object.

        Args:
            pub_key (bytes or IPublicKey): Public key

        Returns:
            TonPublicKey object: TonPublicKey object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(pub_key)
                if isinstance(pub_key, bytes)
                else cls(pub_key))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> TonPublicKey:
        """
        Create from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            TonPublicKey object: TonPublicKey object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes))

    def __init__(self,
                 pub_key: IPublicKey) -> None:
        """
        Construct class.

        Args:
            pub_key (IPublicKey object): Key object

        Raises:
            TonKeyError: If the bytes length is not valid
            TypeError: If the key is not a Ed25519PublicKey object
        """
        if not isinstance(pub_key, Ed25519PublicKey):
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
            TonKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Ed25519PublicKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise TonKeyError("Invalid public key") from ex


class TonPrivateKey:
    """TON private key class."""

    m_priv_key: IPrivateKey

    @classmethod
    def FromBytesOrKeyObject(cls,
                             priv_key: Union[bytes, IPrivateKey]) -> TonPrivateKey:
        """
        Get the private key from key bytes or object.

        Args:
            priv_key (bytes or IPrivateKey): Private key

        Returns:
            TonPrivateKey object: TonPrivateKey object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        return (cls.FromBytes(priv_key)
                if isinstance(priv_key, bytes)
                else cls(priv_key))

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes) -> TonPrivateKey:
        """
        Create from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes))

    def __init__(self,
                 priv_key: IPrivateKey) -> None:
        """
        Construct class.

        Args:
            priv_key (IPrivateKey object): Key object

        Raises:
            TonKeyError: If the bytes length is not valid
            TypeError: If the key is not a Ed25519PrivateKey object
        """
        if not isinstance(priv_key, Ed25519PrivateKey):
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
    def PublicKey(self) -> TonPublicKey:
        """
        Get the public key correspondent to the private one.

        Returns:
            TonPublicKey object: TonPublicKey object
        """
        return TonPublicKey(self.m_priv_key.PublicKey())

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes) -> IPrivateKey:
        """
        Construct key from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Ed25519PrivateKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise TonKeyError("Invalid private key") from ex
