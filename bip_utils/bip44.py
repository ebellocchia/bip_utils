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
from .bip32      import Bip32, Bip32Const
from .bip44_base import Bip44Base
from .P2PKH      import P2PKH


class Bip44Const:
    """ Class container for BIP44 constants. """

    # Public net versions (same of BIP32)
    PUB_NET_VER   = Bip32Const.PUB_NET_VER
    # Private net versions (same of BIP32)
    PRIV_NET_VER  = Bip32Const.PRIV_NET_VER
    # Purpose
    PURPOSE       = Bip32.HardenIndex(44)


class Bip44(Bip44Base):
    """ BIP44 class. """

    def Purpose(self):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns (Bip object):
            Bip object
        """
        return self._PurposeGeneric(self)

    def Coin(self, coin_idx):
        """ Derive a child key from the specified coin type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _CoinGeneric method with the current object as parameter.

        Args:
            coin_idx (Bip44Coins) : coin index, must a Bip44Coins enum

        Returns (Bip object):
            Bip object
        """
        return self._CoinGeneric(self, coin_idx)

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
    def _GetPubNetVersions():
        """ Get public net versions.

        Returns (tuple):
            Private net versions (main net in index 0, test net in index 1)
        """
        return Bip44Const.PUB_NET_VER

    @staticmethod
    def _GetPrivNetVersions():
        """ Get private net versions.

        Returns (tuple):
            Private net versions (main net in index 0, test net in index 1)
        """
        return Bip44Const.PRIV_NET_VER

    @staticmethod
    def _GetAddressGenClass():
        """ Get address generator calls.
        The class shall define the following static method:
            ToAddress(pub_key_bytes, is_testnet = False)

        Returns (object):
            Address generator class
        """
        return P2PKH
