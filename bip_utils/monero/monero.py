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

"""Module for Monero keys computation and derivation."""

# Imports
from __future__ import annotations

from functools import lru_cache
from typing import Optional, Union

from bip_utils.addr import XmrIntegratedAddrEncoder
from bip_utils.ecc import Ed25519MoneroPrivateKey, Ed25519Utils, IPrivateKey, IPublicKey
from bip_utils.monero.conf import MoneroCoinConf, MoneroCoins, MoneroConfGetter
from bip_utils.monero.monero_ex import MoneroKeyError
from bip_utils.monero.monero_keys import MoneroPrivateKey, MoneroPublicKey
from bip_utils.monero.monero_subaddr import MoneroSubaddress
from bip_utils.utils.crypto import Kekkak256


class Monero:
    """
    Monero class.
    It allows to compute Monero keys and addresses/subaddresses.
    """

    m_priv_skey: Optional[MoneroPrivateKey]
    m_priv_vkey: MoneroPrivateKey
    m_pub_skey: MoneroPublicKey
    m_pub_vkey: MoneroPublicKey
    m_coin_conf: MoneroCoinConf
    m_subaddr: MoneroSubaddress

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 coin_type: MoneroCoins = MoneroCoins.MONERO_MAINNET) -> Monero:
        """
        Create from seed bytes.

        Args:
            seed_bytes (bytes)               : Seed bytes
            coin_type (MoneroCoins, optional): Coin type (default: main net)

        Returns:
            Monero object: Monero object
        """
        priv_skey_bytes = (seed_bytes
                           if len(seed_bytes) == Ed25519MoneroPrivateKey.Length()
                           else Kekkak256.QuickDigest(seed_bytes))
        return cls.FromPrivateSpendKey(
            Ed25519Utils.ScalarReduce(priv_skey_bytes),
            coin_type
        )

    @classmethod
    def FromBip44PrivateKey(cls,
                            priv_key: Union[bytes, IPrivateKey],
                            coin_type: MoneroCoins = MoneroCoins.MONERO_MAINNET) -> Monero:
        """
        Create from Bip44 private key bytes.

        Args:
            priv_key (bytes or IPrivateKey)  : Private key
            coin_type (MoneroCoins, optional): Coin type (default: main net)

        Returns:
            Monero object: Monero object
        """
        if not isinstance(priv_key, bytes):
            priv_key = priv_key.Raw().ToBytes()
        return cls.FromPrivateSpendKey(
            Ed25519Utils.ScalarReduce(Kekkak256.QuickDigest(priv_key)),
            coin_type
        )

    @classmethod
    def FromPrivateSpendKey(cls,
                            priv_skey: Union[bytes, IPrivateKey],
                            coin_type: MoneroCoins = MoneroCoins.MONERO_MAINNET) -> Monero:
        """
        Create from private spend key.

        Args:
            priv_skey (bytes or IPrivateKey) : Private spend key
            coin_type (MoneroCoins, optional): Coin type (default: main net)

        Returns:
            Monero object: Monero object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(priv_key=priv_skey,
                   coin_type=coin_type)

    @classmethod
    def FromWatchOnly(cls,
                      priv_vkey: Union[bytes, IPrivateKey],
                      pub_skey: Union[bytes, IPublicKey],
                      coin_type: MoneroCoins = MoneroCoins.MONERO_MAINNET) -> Monero:
        """
        Create from private view key and public spend key (i.e. watch-only wallet).

        Args:
            priv_vkey (bytes or IPrivateKey) : Private view key
            pub_skey (bytes or IPublicKey)   : Public spend key
            coin_type (MoneroCoins, optional): Coin type (default: main net)

        Returns:
            Monero object: Monero object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(priv_key=priv_vkey,
                   pub_key=pub_skey,
                   coin_type=coin_type)

    def __init__(self,
                 priv_key: Union[bytes, IPrivateKey],
                 pub_key: Optional[Union[bytes, IPublicKey]] = None,
                 coin_type: MoneroCoins = MoneroCoins.MONERO_MAINNET) -> None:
        """
        Construct class.

        Args:
            priv_key (bytes or IPrivateKey)  : Private key (view key if watch-only wallet, otherwise spend key)
            pub_key (bytes or IPublicKey)    : Public spend key (only needed for watch-only wallets, otherwise None)
            coin_type (MoneroCoins, optional): Coin type (default: main net)

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """

        # Private key object
        if pub_key is None:
            self.m_priv_skey = MoneroPrivateKey.FromBytesOrKeyObject(priv_key)
            self.m_priv_vkey = self.__ViewFromSpendKey(self.m_priv_skey)
            self.m_pub_skey = self.m_priv_skey.PublicKey()
            self.m_pub_vkey = self.m_priv_vkey.PublicKey()
        # Watch-only object
        else:
            self.m_priv_skey = None
            self.m_priv_vkey = MoneroPrivateKey.FromBytesOrKeyObject(priv_key)
            self.m_pub_skey = MoneroPublicKey.FromBytesOrKeyObject(pub_key)
            self.m_pub_vkey = self.m_priv_vkey.PublicKey()

        self.m_coin_conf = MoneroConfGetter.GetConfig(coin_type)
        self.m_subaddr = MoneroSubaddress(self.m_priv_vkey, self.m_pub_skey, self.m_pub_vkey)

    def IsWatchOnly(self) -> bool:
        """
        Return if it's a watch-only object.

        Returns:
            bool: True if watch-only, false otherwise
        """
        return self.m_priv_skey is None

    def CoinConf(self) -> MoneroCoinConf:
        """
        Return coin configuration.

        Returns:
            MoneroCoinConf object: MoneroCoinConf object
        """
        return self.m_coin_conf

    def PrivateSpendKey(self) -> MoneroPrivateKey:
        """
        Return the private spend key.

        Returns:
            MoneroPrivateKey object: MoneroPrivateKey object

        Raises:
            MoneroKeyError: If the class is watch-only
        """
        if self.IsWatchOnly():
            raise MoneroKeyError("Watch-only class has not a private spend key")

        assert isinstance(self.m_priv_skey, MoneroPrivateKey)
        return self.m_priv_skey

    def PrivateViewKey(self) -> MoneroPrivateKey:
        """
        Return the private view key.

        Returns:
            MoneroPrivateKey object: MoneroPrivateKey object
        """
        return self.m_priv_vkey

    def PublicSpendKey(self) -> MoneroPublicKey:
        """
        Return the public spend key.

        Returns:
            MoneroPublicKey object: MoneroPublicKey object
        """
        return self.m_pub_skey

    def PublicViewKey(self) -> MoneroPublicKey:
        """
        Return the public view key.

        Returns:
            MoneroPublicKey object: MoneroPublicKey object
        """
        return self.m_pub_vkey

    @lru_cache()
    def IntegratedAddress(self,
                          payment_id: bytes) -> str:
        """
        Return the integrated address with the specified payment ID.

        Args:
            payment_id (bytes): Payment ID

        Returns:
            str: Integrated address string
        """
        return XmrIntegratedAddrEncoder.EncodeKey(self.m_pub_skey.KeyObject(),
                                                  pub_vkey=self.m_pub_vkey.KeyObject(),
                                                  net_ver=self.m_coin_conf.IntegratedAddrNetVersion(),
                                                  payment_id=payment_id)

    @lru_cache()
    def PrimaryAddress(self) -> str:
        """
        Return the primary address.

        Returns:
            str: Primary address string
        """
        return self.m_subaddr.ComputeAndEncodeKeys(0,
                                                   0,
                                                   self.m_coin_conf.AddrNetVersion())

    @lru_cache()
    def Subaddress(self,
                   minor_idx: int,
                   major_idx: int = 0) -> str:
        """
        Return the specified subaddress.

        Args:
            minor_idx (int)          : Minor index (i.e. subaddress index)
            major_idx (int, optional): Major index (i.e. account index, default: 0)

        Returns:
            str: Subaddress string

        Raises:
            ValueError: If one of the indexes is not valid
        """
        if minor_idx == 0 and major_idx == 0:
            return self.PrimaryAddress()

        return self.m_subaddr.ComputeAndEncodeKeys(minor_idx,
                                                   major_idx,
                                                   self.m_coin_conf.SubaddrNetVersion())

    @staticmethod
    def __ViewFromSpendKey(priv_skey: MoneroPrivateKey) -> MoneroPrivateKey:
        """
        Get the private view key from the private spend key.

        Args:
            priv_skey (MoneroPrivateKey object): Private spend key

        Returns:
            MoneroPrivateKey object: Private view key
        """
        priv_vkey_bytes = Ed25519Utils.ScalarReduce(
            Kekkak256.QuickDigest(priv_skey.Raw().ToBytes())
        )
        return MoneroPrivateKey.FromBytes(priv_vkey_bytes)
