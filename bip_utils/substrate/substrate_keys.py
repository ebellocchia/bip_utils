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
from bip_utils.addr import SubstrateSr25519Addr
from bip_utils.conf import SubstrateCoinConf
from bip_utils.ecc import IPrivateKey, IPublicKey, Sr25519PrivateKey, Sr25519PublicKey
from bip_utils.substrate.substrate_ex import SubstrateKeyError
from bip_utils.utils import DataBytes


class SubstratePublicKey:
    """ Substrate public key class. """

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes,
                  coin_conf: SubstrateCoinConf) -> SubstratePublicKey:
        """ Create from bytes.

        Args:
            key_bytes (bytes)                   : Key bytes
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes),
                   coin_conf)

    def __init__(self,
                 pub_key: IPublicKey,
                 coin_conf: SubstrateCoinConf) -> None:
        """ Construct class.

        Args:
            pub_key (IPublicKey object)         : Key object
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If the bytes length is not valid
            TypeError: If the key is not a Sr25519PublicKey object
        """
        if not isinstance(pub_key, Sr25519PublicKey):
            raise TypeError("Invalid public key object type")
        self.m_pub_key = pub_key
        self.m_coin_conf = coin_conf

    def KeyObject(self) -> IPublicKey:
        """ Return the key object.

        Returns:
            IPublicKey object: Key object
        """
        return self.m_pub_key

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

    @lru_cache()
    def ToAddress(self) -> str:
        """ Return the address correspondent to the public key.

        Returns:
            str: Address string
        """
        return SubstrateSr25519Addr.EncodeKey(self.m_pub_key,
                                              self.m_coin_conf.SS58Format())

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes) -> IPublicKey:
        """ Construct key from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            SubstrateKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Sr25519PublicKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise SubstrateKeyError("Invalid public key") from ex


class SubstratePrivateKey:
    """ Substrate private key class. """

    @classmethod
    def FromBytes(cls,
                  key_bytes: bytes,
                  coin_conf: SubstrateCoinConf) -> SubstratePrivateKey:
        """ Create from bytes.

        Args:
            key_bytes (bytes)                   : Key bytes
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If the key constructed from the bytes is not valid
        """
        return cls(cls.__KeyFromBytes(key_bytes),
                   coin_conf)

    def __init__(self,
                 priv_key: IPrivateKey,
                 coin_conf: SubstrateCoinConf) -> None:
        """ Construct class.

        Args:
            priv_key (IPrivateKey object) : Key object
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If the bytes length is not valid
            TypeError: If the key is not a Sr25519PrivateKey object
        """
        if not isinstance(priv_key, Sr25519PrivateKey):
            raise TypeError("Invalid private key object type")
        self.m_priv_key = priv_key
        self.m_coin_conf = coin_conf

    def KeyObject(self) -> IPrivateKey:
        """ Return the key object.

        Returns:
            IPrivateKey object: Key object
        """
        return self.m_priv_key

    @lru_cache()
    def Raw(self) -> DataBytes:
        """ Return raw private key.

        Returns:
            DataBytes object: DataBytes object
        """
        return self.m_priv_key.Raw()

    @lru_cache()
    def PublicKey(self) -> SubstratePublicKey:
        """ Get the public key correspondent to the private one.

        Returns:
            SubstratePublicKey object: SubstratePublicKey object
        """
        return SubstratePublicKey(self.m_priv_key.PublicKey(),
                                  self.m_coin_conf)

    @staticmethod
    def __KeyFromBytes(key_bytes: bytes) -> IPrivateKey:
        """ Construct key from bytes.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            SubstrateKeyError: If the key constructed from the bytes is not valid
        """
        try:
            return Sr25519PrivateKey.FromBytes(key_bytes)
        except ValueError as ex:
            raise SubstrateKeyError("Invalid private key") from ex
