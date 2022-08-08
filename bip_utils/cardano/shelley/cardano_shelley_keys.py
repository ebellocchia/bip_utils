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

"""Module for Cardano Shelley keys handling."""

# Imports
from functools import lru_cache

from bip_utils.addr import AdaShelleyAddrEncoder, AdaShelleyStakingAddrEncoder
from bip_utils.bip.bip32 import Bip32PrivateKey, Bip32PublicKey
from bip_utils.bip.conf.common import BipCoinConf


class CardanoShelleyPublicKeys:
    """
    Cardano Shelley public key class.
    It contains 2 CIP-1852 public keys (address + staking) and allows to get the Cardano Shelley address from them.
    """

    m_pub_addr_key: Bip32PublicKey
    m_pub_sk_key: Bip32PublicKey
    m_coin_conf: BipCoinConf

    def __init__(self,
                 pub_addr_key: Bip32PublicKey,
                 pub_sk_key: Bip32PublicKey,
                 coin_conf: BipCoinConf) -> None:
        """
        Construct class.

        Args:
            pub_addr_key (Bip32PublicKey object): Bip32PublicKey object (address)
            pub_sk_key (Bip32PublicKey object)  : Bip32PublicKey object (staking)
            coin_conf (BipCoinConf object)      : BipCoinConf object
        """
        self.m_pub_addr_key = pub_addr_key
        self.m_pub_sk_key = pub_sk_key
        self.m_coin_conf = coin_conf

    def AddressKey(self) -> Bip32PublicKey:
        """
        Get the address public key.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return self.m_pub_addr_key

    def RewardKey(self) -> Bip32PublicKey:
        """
        Alias for StakingKey.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return self.StakingKey()

    def StakingKey(self) -> Bip32PublicKey:
        """
        Get the staking address public key.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return self.m_pub_sk_key

    def ToRewardAddress(self) -> str:
        """
        Alias for ToStakingAddress.

        Returns:
            str: Reward address string

        Raises:
            ValueError: If the public key is not correspondent to an address index level
        """
        return self.ToStakingAddress()

    @lru_cache()
    def ToStakingAddress(self) -> str:
        """
        Return the staking address correspondent to the public key.

        Returns:
            str: Staking address string

        Raises:
            ValueError: If the public key is not correspondent to an address index level
        """
        return AdaShelleyStakingAddrEncoder.EncodeKey(self.m_pub_sk_key.KeyObject(),
                                                      **self.m_coin_conf.AddrParams())

    @lru_cache()
    def ToAddress(self) -> str:
        """
        Return the address correspondent to the public key.

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not correspondent to an address index level
        """
        return AdaShelleyAddrEncoder.EncodeKey(self.m_pub_addr_key.KeyObject(),
                                               pub_skey=self.m_pub_sk_key.KeyObject(),
                                               **self.m_coin_conf.AddrParams())


class CardanoShelleyPrivateKeys:
    """
    Cardano Shelley private key class.
    It contains 2 BIP32 private keys (address + staking).
    """

    m_priv_addr_key: Bip32PrivateKey
    m_priv_sk_key: Bip32PrivateKey
    m_coin_conf: BipCoinConf

    def __init__(self,
                 priv_addr_key: Bip32PrivateKey,
                 priv_sk_key: Bip32PrivateKey,
                 coin_conf: BipCoinConf) -> None:
        """
        Construct class.

        Args:
            priv_addr_key (Bip32PrivateKey object): Bip32PrivateKey object (address)
            priv_sk_key (Bip32PrivateKey object)  : Bip32PrivateKey object (staking)
            coin_conf (BipCoinConf object)        : BipCoinConf object
        """
        self.m_priv_addr_key = priv_addr_key
        self.m_priv_sk_key = priv_sk_key
        self.m_coin_conf = coin_conf

    def AddressKey(self) -> Bip32PrivateKey:
        """
        Get the address private key.

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object
        """
        return self.m_priv_addr_key

    def RewardKey(self) -> Bip32PrivateKey:
        """
        Alias for StakingKey.

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object
        """
        return self.StakingKey()

    def StakingKey(self) -> Bip32PrivateKey:
        """
        Get the staking address private key.

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object
        """
        return self.m_priv_sk_key

    @lru_cache()
    def PublicKeys(self) -> CardanoShelleyPublicKeys:
        """
        Get the public keys correspondent to the private ones.

        Returns:
            CardanoShelleyPublicKeys object: CardanoShelleyPublicKeys object
        """
        return CardanoShelleyPublicKeys(self.m_priv_addr_key.PublicKey(),
                                        self.m_priv_sk_key.PublicKey(),
                                        self.m_coin_conf)
