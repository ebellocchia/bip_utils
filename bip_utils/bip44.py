# Copyright (c) 2020 Emanuele Bellocchia
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

# BIP-0044 specifications:
# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

# Imports
from .bip32             import Bip32, Bip32Const
from .bip44_base        import Bip44Base, Bip44Coins
from .bip44_coin_helper import *


class Bip44Const:
    """ Class container for BIP44 constants. """

    # Purpose
    PURPOSE = Bip32.HardenIndex(44)

    # Map from Bip44Coins to helper classes
    COIN_TO_HELPER = \
        {
            Bip44Coins.BITCOIN  : BitcoinHelper,
            Bip44Coins.LITECOIN : LitecoinHelper,
            Bip44Coins.DOGECOIN : DogecoinHelper,
            Bip44Coins.ETHEREUM : EthereumHelper,
        }


class Bip44(Bip44Base):
    """ BIP44 class. """

    def Purpose(self):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns (Bip object):
            Bip object
        """
        return self._PurposeGeneric(self)

    def Coin(self):
        """ Derive a child key from the coin type specified at construction and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _CoinGeneric method with the current object as parameter.

        Returns (Bip object):
            Bip object
        """
        return self._CoinGeneric(self)

    def Account(self, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AccountGeneric method with the current object as parameter.

        Args:
            acc_idx (int) : account index

        Returns (Bip object):
            Bip object
        """
        return self._AccountGeneric(self, acc_idx)

    def Change(self, chain_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _ChangeGeneric method with the current object as parameter.

        Args:
            chain_idx (Bip44Changes) : chain index, must a Bip44Changes enum

        Returns (Bip object):
            Bip object
        """
        return self._ChangeGeneric(self, chain_idx)

    def AddressIndex(self, addr_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AddressIndexGeneric method with the current object as parameter.

        Args:
            addr_idx (int) : address index

        Returns (Bip object):
            Bip object
        """
        return self._AddressIndexGeneric(self, addr_idx)

    @staticmethod
    def _GetPurpose():
        """ Get purpose.

        Returns (int):
            Purpose
        """
        return Bip44Const.PURPOSE

    @staticmethod
    def _GetMainNetVersions(coin_idx):
        """ Get main net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        return Bip44Const.COIN_TO_HELPER[coin_idx].GetMainNetVersions()

    @staticmethod
    def _GetTestNetVersions(coin_idx):
        """ Get test net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        return Bip44Const.COIN_TO_HELPER[coin_idx].GetTestNetVersions()

    @staticmethod
    def _GetComputeAddressFct(coin_idx):
        """ Compute compute address function.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (function):
            Compute address function
        """
        return Bip44Const.COIN_TO_HELPER[coin_idx].ComputeAddress

    @staticmethod
    def _GetWifNetVersions(coin_idx):
        """ Get WIF net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            WIF net versions (public at key "pub", private at key "priv")
        """
        return Bip44Const.COIN_TO_HELPER[coin_idx].GetWifNetVersions()
