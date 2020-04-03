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

# Bip0044 specifications:
# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

# Imports
from abc    import ABC, abstractmethod
from enum   import IntEnum, unique
from .bip32 import Bip32, Bip32Const
from .wif   import WifEncoder


@unique
class Bip44Coins(IntEnum):
    """ Enumerative for BIP44 coins. Only Bitcoin is present but it can be extended. """

    BITCOIN         = 0,
    BITCOIN_TESTNET = 1,
    ETHEREUM        = 60,


@unique
class Bip44Changes(IntEnum):
    """ Enumerative for BIP44 changes. """

    CHAIN_EXT = 0,
    CHAIN_INT = 1,


class Bip44BaseConst:
    """ Class container for BIP44 base constants. """

    # Master depth
    MASTER_DEPTH        = 0
    # Purpose depth
    PURPOSE_DEPTH       = 1
    # Coin depth
    COIN_DEPTH          = 2
    # Account depth
    ACCOUNT_DEPTH       = 3
    # Chain depth
    CHAIN_DEPTH         = 4
    # Address depth
    ADDRESS_INDEX_DEPTH = 5


class Bip44Base(ABC):
    """ BIP44 base class.
    It allows coin, account, chain and address keys generation in according to BIP44 or its extension (e.g. BIP49, BIP84).
    The class is meant to be derived by classes implementing BIP44 or its extension.
    """

    def __init__(self, bip32_obj):
        """ Construct class from a Bip32 object.

        Args:
            bip32_obj (Bip32 object) : Bip32 object
        """
        self.m_bip32 = bip32_obj

    @classmethod
    def FromSeed(cls, seed_bytes, is_testnet = False):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified seed (e.g. BIP39 seed).
        The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
        or purpose keys, you have to specify here if it's a test net.

        Args:
            seed_bytes (bytes)          : seed bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (Bip object):
            Bip object
        """
        return cls(Bip32.FromSeed(seed_bytes, is_testnet))

    @classmethod
    def FromExtendedKey(cls, key_str):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified extended key.

        Args:
            key_str (str) : extended key string

        Returns (Bip object):
            Bip object
        """
        return cls(Bip32.FromExtendedKey(key_str, cls._GetPubNetVersions(), cls._GetPrivNetVersions()))

    def PublicKey(self, extended = True):
        """ Return the public key.

        Args:
            extended (bool) : if true, the extended key encoded in base58 will be returned, oitherwise the key bytes

        Returns (str):
            Public key
        """
        return self.m_bip32.ExtendedPublicKey(self._GetPubNetVersions()) if extended else self.m_bip32.PublicKeyBytes()

    def PrivateKey(self, extended = True):
        """ Return the private key.

        Args:
            extended (bool) : if true, the extended key encoded in base58 will be returned, oitherwise the key bytes

        Returns (str):
            Private key
        """
        return self.m_bip32.ExtendedPrivateKey(self._GetPrivNetVersions()) if extended else self.m_bip32.PrivateKeyBytes()

    def Address(self):
        """ Return address related to the current public key.

        Returns (str):
            Address string
        """
        return self._GetAddressGenClass().ToAddress(self.m_bip32.PublicKeyBytes(), self.m_bip32.IsTestNet())

    def IsMasterLevel(self):
        """ Return if it's a master path.

        Returns (bool):
            True if master path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.MASTER_DEPTH

    def IsPurposeLevel(self):
        """ Return if it's a purpose path.

        Returns (bool):
            True if purpose path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.PURPOSE_DEPTH

    def IsCoinLevel(self):
        """ Return if it's a coin path.

        Returns (bool):
            True if coin path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.COIN_DEPTH

    def IsAccountLevel(self):
        """ Return if it's a account path.

        Returns (bool):
            True if account path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.ACCOUNT_DEPTH

    def IsChangeLevel(self):
        """ Return if it's a chain path.

        Returns (bool):
            True if chain path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.CHAIN_DEPTH

    def IsAddressIndexLevel(self):
        """ Return if it's a address index path.

        Returns (bool):
            True if address index path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.ADDRESS_INDEX_DEPTH

    def WalletImportFormat(self):
        """ Return the current private key encoded in WIF.

        Returns (str):
            Address string
        """
        return WifEncoder.Encode(self.m_bip32.PrivateKeyBytes())

    @abstractmethod
    def Purpose(self):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _PurposeGeneric method with the current object as parameter.

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Coin(self, coin_idx):
        """ Derive a child key from the specified coin type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _CoinGeneric method with the current object as parameter.

        Args:
            coin_idx (Bip44Coins) : coin index, must a Bip44Coins enum

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Account(self, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _AccountGeneric method with the current object as parameter.

        Args:
            acc_idx (int) : account index

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Change(self, chain_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _ChangeGeneric method with the current object as parameter.

        Args:
            chain_idx (Bip44Changes) : chain index, must a Bip44Changes enum

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def AddressIndex(self, addr_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _AddressIndexGeneric method with the current object as parameter.

        Args:
            addr_idx (int) : address index

        Returns (Bip object):
            Bip object
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetPurpose():
        """ Get purpose.

        Returns (int):
            Purpose
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetPubNetVersions():
        """ Get public net versions.

        Returns (tuple):
            Private net versions (main net in index 0, test net in index 1)
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetPrivNetVersions():
        """ Get private net versions.

        Returns (tuple):
            Private net versions (main net in index 0, test net in index 1)
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetAddressGenClass():
        """ Get address generator calls.
        The class shall define the following static method:
            ToAddress(pub_key_bytes, is_testnet = False)

        Returns (object):
            Address generator class
        """
        pass

    @classmethod
    def _PurposeGeneric(cls, bip_obj):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        RuntimeError is raised is chain depth is not suitable for deriving keys.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)       : address index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsMasterLevel(bip_obj):
            raise RuntimeError("Current depth (%d) is not suitable for deriving purpose" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(cls._GetPurpose()))

    @classmethod
    def _CoinGeneric(cls, bip_obj, coin_idx):
        """ Derive a child key from the specified coin type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        TypeError is raised if coin type is not a Bip44Coins enum.
        RuntimeError is raised is chain depth is not suitable for deriving keys.

        Args:
            bip_obj (BIP object)  : Bip object (e.g. BIP44, BIP49, BIP84)
            coin_idx (Bip44Coins) : coin index, must a Bip44Coins enum

        Returns (Bip object):
            Bip object
        """
        if not isinstance(coin_idx, Bip44Coins):
            raise TypeError("Coin index is not an enumerative of Bip44Coins")

        if not cls.IsPurposeLevel(bip_obj):
            raise RuntimeError("Current depth (%d) is not suitable for deriving coin" % bip_obj.m_bip32.Depth())

        # Set test net depending on the coin
        if coin_idx == Bip44Coins.BITCOIN_TESTNET:
            bip_obj.m_bip32.SetTestNet(True)

        return cls(bip_obj.m_bip32.ChildKey(Bip32.HardenIndex(coin_idx)))

    @classmethod
    def _AccountGeneric(cls, bip_obj, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        RuntimeError is raised is chain depth is not suitable for deriving keys.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            acc_idx (int)        : account index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsCoinLevel(bip_obj):
            raise RuntimeError("Current depth (%d) is not suitable for deriving account" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(Bip32.HardenIndex(acc_idx)))

    @classmethod
    def _ChangeGeneric(cls, bip_obj, chain_idx):
        """ Derive a child key from the specified chain type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        TypeError is raised if chain type is not a Bip44Changes enum.
        RuntimeError is raised is chain depth is not suitable for deriving keys.

        Args:
            bip_obj (BIP object)    : Bip object (e.g. BIP44, BIP49, BIP84)
            chain_idx (Bip44Changes) : chain index, must a Bip44Changes enum

        Returns (Bip object):
            Bip object
        """
        if not isinstance(chain_idx, Bip44Changes):
            raise TypeError("Chain index is not an enumerative of Bip44Changes")

        if not cls.IsAccountLevel(bip_obj):
            raise RuntimeError("Current depth (%d) is not suitable for deriving chain" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(chain_idx))

    @classmethod
    def _AddressIndexGeneric(cls, bip_obj, addr_idx):
        """ Derive a child key from the specified address index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        RuntimeError is raised is chain depth is not suitable for deriving keys.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)       : address index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsChangeLevel(bip_obj):
            raise RuntimeError("Current depth (%d) is not suitable for deriving address" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(addr_idx))
