# Copyright (c) 2022 Emanuele Bellocchia
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

"""
Module for Cardano Shelley keys derivation.
Reference: https://cips.cardano.org/cips/cip11
"""

# Imports
from __future__ import annotations

import copy
from functools import lru_cache

from bip_utils.addr import AdaShelleyStakingAddrEncoder
from bip_utils.bip.bip44_base import Bip44Base, Bip44Changes, Bip44Levels
from bip_utils.cardano.cip1852 import Cip1852
from bip_utils.cardano.shelley.cardano_shelley_keys import CardanoShelleyPrivateKeys, CardanoShelleyPublicKeys


class CardanoShelley:
    """
    Cardano Shelley class.
    It allows keys derivation and addresses computation (including the staking one) in according to Cardano Shelley.
    """

    m_bip_obj: Bip44Base
    m_bip_sk_obj: Bip44Base

    @classmethod
    def FromCip1852Object(cls,
                          bip_obj: Bip44Base) -> CardanoShelley:
        """
        Create a CardanoShelley object from the specified Cip1852 object.

        Args:
            bip_obj (Bip44Base object): Bip44Base object

        Returns:
            CardanoShelley object: CardanoShelley object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        if not isinstance(bip_obj, Cip1852):
            raise ValueError("The Bip object shall be a Cip1852 instance")
        return cls(bip_obj,
                   cls.__DeriveStakingKeys(bip_obj))

    def __init__(self,
                 bip_obj: Bip44Base,
                 bip_sk_obj: Bip44Base) -> None:
        """
        Construct class.

        Args:
            bip_obj (Bip44Base object)   : Bip44Base object
            bip_sk_obj (Bip44Base object): Bip44Base object (staking)

        Raises:
            ValueError: If the bip_sk_obj object is below account level
        """
        if bip_obj.Level() < Bip44Levels.ACCOUNT:
            raise ValueError("The bip_obj shall not be below account level")
        if bip_sk_obj.Level() != Bip44Levels.ADDRESS_INDEX:
            raise ValueError("The bip_sk_obj shall be of address index level")
        self.m_bip_obj = bip_obj
        self.m_bip_sk_obj = bip_sk_obj

    @lru_cache()
    def PublicKeys(self) -> CardanoShelleyPublicKeys:
        """
        Return the public keys.

        Returns:
            CardanoShelleyPublicKeys object: CardanoShelleyPublicKeys object
        """
        return CardanoShelleyPublicKeys(self.m_bip_obj.PublicKey().Bip32Key(),
                                        self.m_bip_sk_obj.PublicKey().Bip32Key(),
                                        self.m_bip_obj.CoinConf())

    @lru_cache()
    def PrivateKeys(self) -> CardanoShelleyPrivateKeys:
        """
        Return the private keys.

        Returns:
            CardanoShelleyPrivateKeys object: CardanoShelleyPrivateKeys object

        Raises:
            Bip32KeyError: If the Bip32 object is public-only
        """
        return CardanoShelleyPrivateKeys(self.m_bip_obj.PrivateKey().Bip32Key(),
                                         self.m_bip_sk_obj.PrivateKey().Bip32Key(),
                                         self.m_bip_obj.CoinConf())

    def RewardObject(self) -> Bip44Base:
        """
        Alias for StakingObject.

        Returns:
            Bip44Base object: Bip44Base object
        """
        return self.StakingObject()

    def StakingObject(self) -> Bip44Base:
        """
        Return the staking object.

        Returns:
            Bip44Base object: Bip44Base object
        """
        return self.m_bip_sk_obj

    def IsPublicOnly(self) -> bool:
        """
        Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_bip_obj.IsPublicOnly()

    def Change(self,
               change_type: Bip44Changes) -> CardanoShelley:
        """
        Derive a child key from the specified change type and return a new CardanoShelley object.

        Args:
            change_type (Bip44Changes): Change type, must a Bip44Changes enum

        Returns:
            CardanoShelley object: CardanoShelley object

        Raises:
            TypeError: If change type is not a Bip44Changes enum
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return CardanoShelley(self.m_bip_obj.Change(change_type),
                              self.m_bip_sk_obj)

    def AddressIndex(self,
                     addr_idx: int) -> CardanoShelley:
        """
        Derive a child key from the specified address index and return a new CardanoShelley object.

        Args:
            addr_idx (int): Address index

        Returns:
            CardanoShelley object: CardanoShelley object

        Raises:
            Cip1852DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return CardanoShelley(self.m_bip_obj.AddressIndex(addr_idx),
                              self.m_bip_sk_obj)

    @staticmethod
    def __DeriveStakingKeys(bip_obj: Bip44Base) -> Bip44Base:
        """
        Derive staking keys from a Bip44Base object.

        Args:
            bip_obj (Bip44Base object): Bip44Base object

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
        """

        # Create a new configuration with the staking address class (no need to deep-copying)
        coin_conf = copy.copy(bip_obj.CoinConf())
        coin_conf.m_addr_cls = AdaShelleyStakingAddrEncoder
        # Create Cip1852 object for staking keys
        return Cip1852(bip_obj.Bip32Object().DerivePath("2/0"),
                       coin_conf)
