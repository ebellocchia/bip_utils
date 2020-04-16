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


# Imports
from abc            import ABC, abstractmethod
from enum           import IntEnum, unique
from .bip32_utils   import Bip32Utils
from .bip32         import Bip32
from .bip_keys      import BipPrivateKey, BipPublicKey
from .bip44_base_ex import Bip44DepthError, Bip44CoinNotAllowedError


@unique
class Bip44Coins(IntEnum):
    """ Enumerative for BIP44 coins. Only some coins are present but it can be extended. """

    BITCOIN          = 0,
    LITECOIN         = 2,
    DOGECOIN         = 3,
    DASH             = 5,
    ETHEREUM         = 60,
    RIPPLE           = 144,
    # Test nets. Special indexes are used here, they are converted to 1 internally
    BITCOIN_TESTNET  = -1,
    LITECOIN_TESTNET = -2,
    DOGECOIN_TESTNET = -3,
    DASH_TESTNET     = -4,


@unique
class Bip44Changes(IntEnum):
    """ Enumerative for BIP44 changes. """

    CHAIN_EXT = 0,
    CHAIN_INT = 1,


@unique
class Bip44Levels(IntEnum):
    """ Enumerative for BIP44 levels. """

    MASTER        = 0,
    PURPOSE       = 1,
    COIN          = 2,
    ACCOUNT       = 3,
    CHANGE        = 4,
    ADDRESS_INDEX = 5,


class Bip44BaseConst:
    """ Class container for BIP44 base constants. """

    # Test net coin index
    TEST_NET_COIN_IDX   = 1


class Bip44Base(ABC):
    """ BIP44 base class.
    It allows coin, account, chain and address keys generation in according to BIP44 or its extension (e.g. BIP49, BIP84).
    The class is meant to be derived by classes implementing BIP44 or its extension.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls, seed_bytes, coin_idx):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified seed (e.g. BIP39 seed).
        The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
        or purpose keys, you have to specify here if it's a test net.

        Args:
            seed_bytes (bytes)   : Seed bytes
            coin_idx (Bip44Coins): Coin index, must be a Bip44Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin index is not a Bip44Coins enum
            ValueError: If the seed is too short
            Bip44CoinNotAllowedError: If the coin is not allowed to derive from the BIP specification
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        if not cls.IsCoinAllowed(coin_idx):
            raise Bip44CoinNotAllowedError("Coin %s cannot derive from %s specification" % (coin_idx, cls.SpecName()))
        return cls(Bip32.FromSeed(seed_bytes, cls._GetCoinClass(coin_idx).KeyNetVersions()), coin_idx)

    @classmethod
    def FromExtendedKey(cls, key_str, coin_idx):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified extended key.

        Args:
            key_str (str)        : Extended key string
            coin_idx (Bip44Coins): Coin index, must be a Bip44Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin index is not a Bip44Coins enum
            Bip44CoinNotAllowedError: If the coin is not allowed to derive from the BIP specification
            Bip32KeyError: If the extended key is not valid
        """
        if not cls.IsCoinAllowed(coin_idx):
            raise Bip44CoinNotAllowedError("Coin %s cannot derive from %s specification" % (coin_idx, cls.SpecName()))
        return cls(Bip32.FromExtendedKey(key_str, cls._GetCoinClass(coin_idx).KeyNetVersions()), coin_idx)

    #
    # Public methods
    #

    def __init__(self, bip32_obj, coin_idx):
        """ Construct class from a Bip32 object and coin type.

        Args:
            bip32_obj (Bip32 object): Bip32 object
            coin_idx (Bip44Coins)   : Coin index, must be a Bip44Coins enum

        Returns:
            Bip44DepthError: If the Bip32 object depth is not valid
        """

        # If the Bip32 is public-only, the depth shall start from the account level because hardened derivation is
        # used below it, which is not possible with public keys
        if bip32_obj.IsPublicOnly():
            if bip32_obj.Depth() < Bip44Levels.ACCOUNT or \
               bip32_obj.Depth() > Bip44Levels.ADDRESS_INDEX:
                raise Bip44DepthError("Depth of the public-only Bip32 object (%d) is below account level or beyond address index level" % bip32_obj.Depth())
        # If the Bip32 object is not public-only, any depth is fine as long as it is not greater than address index level
        else:
            if bip32_obj.Depth() > Bip44Levels.ADDRESS_INDEX:
                raise Bip44DepthError("Depth of the Bip32 object (%d) is beyond address index level" % bip32_obj.Depth())

        # Finally, initialize class
        self.m_bip32      = bip32_obj
        self.m_coin_idx   = coin_idx
        self.m_coin_class = self._GetCoinClass(coin_idx)

    def PublicKey(self):
        """ Return the public key.

        Returns:
            BipPublicKey object: BipPublicKey object

        """
        return BipPublicKey(self.m_bip32, self.m_coin_class)

    def PrivateKey(self):
        """ Return the private key.

        Returns:
            BipPrivateKey object: BipPrivateKey object

        Raises:
            Bip32KeyError: If the Bip32 object is public-only
        """
        return BipPrivateKey(self.m_bip32, self.m_coin_class)

    def CoinClass(self):
        """ Get coin class.

        Returns:
            BipCoinBase child object: BipCoinBase child object
        """
        return self.m_coin_class

    def IsPublicOnly(self):
        """ Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_bip32.IsPublicOnly()

    def IsLevel(self, level_idx):
        """ Return if the current depth is the specified one.

        Args:
            level_idx (int): Level to be checked

        Returns:
            bool: True if it's the specified level, false otherwise

        Raises:
            TypeError: If the level index is not a Bip44Levels enum
        """
        if not isinstance(level_idx, Bip44Levels):
            raise TypeError("Level is not an enumerative of Bip44Levels")

        return self.m_bip32.Depth() == level_idx

    #
    # Class methods ("protected", in the sense that they are called only internally)
    #

    @classmethod
    def _PurposeGeneric(cls, bip_obj):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base child object): Bip44Base child object (e.g. BIP44, BIP49, BIP84)

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.MASTER):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving purpose" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(cls._GetPurpose()), bip_obj.m_coin_idx)

    @classmethod
    def _CoinGeneric(cls, bip_obj):
        """ Derive a child key from the coin type specified at construction and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base child object): Bip44Base child object (e.g. BIP44, BIP49, BIP84)

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.PURPOSE):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving coin" % bip_obj.m_bip32.Depth())

        coin_idx = Bip44BaseConst.TEST_NET_COIN_IDX if bip_obj.m_coin_class.IsTestNet() else bip_obj.m_coin_idx

        return cls(bip_obj.m_bip32.ChildKey(Bip32Utils.HardenIndex(coin_idx)), bip_obj.m_coin_idx)

    @classmethod
    def _AccountGeneric(cls, bip_obj, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base child object): Bip44Base child object (e.g. BIP44, BIP49, BIP84)
            acc_idx (int)                   : Account index

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.COIN):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving account" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(Bip32Utils.HardenIndex(acc_idx)), bip_obj.m_coin_idx)

    @classmethod
    def _ChangeGeneric(cls, bip_obj, change_idx):
        """ Derive a child key from the specified chain type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base child object): Bip44Base child object (e.g. BIP44, BIP49, BIP84)
            change_idx (Bip44Changes)       : change index, must a Bip44Changes enum

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            TypeError: If chain index is not a Bip44Changes enum
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not isinstance(change_idx, Bip44Changes):
            raise TypeError("Change index is not an enumerative of Bip44Changes")

        if not cls.IsLevel(bip_obj, Bip44Levels.ACCOUNT):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving change" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(change_idx), bip_obj.m_coin_idx)

    @classmethod
    def _AddressIndexGeneric(cls, bip_obj, addr_idx):
        """ Derive a child key from the specified address index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base child object): Bip44Base child object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)                  : Address index

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.CHANGE):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving address" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(addr_idx), bip_obj.m_coin_idx)

    #
    # Abstract methods
    #

    @abstractmethod
    def Purpose(self):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Coin(self):
        """ Derive a child key from the coin type specified at construction and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _CoinGeneric method with the current object as parameter.

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Account(self, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AccountGeneric method with the current object as parameter.

        Args:
            acc_idx (int): Account index

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Change(self, change_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _ChangeGeneric method with the current object as parameter.

        Args:
            change_idx (Bip44Changes): Change index, must a Bip44Changes enum

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            TypeError: If chain index is not a Bip44Changes enum
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def AddressIndex(self, addr_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AddressIndexGeneric method with the current object as parameter.

        Args:
            addr_idx (int): Address index

        Returns:
            Bip44Base child object: Bip44Base child object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @staticmethod
    @abstractmethod
    def SpecName():
        """ Get specification name.

        Returns:
            str: Specification name
        """
        pass

    @staticmethod
    @abstractmethod
    def IsCoinAllowed(coin_idx):
        """ Get if the specified coin is allowed.

        Args:
            coin_idx (Bip44Coins): Coin index, must be a Bip44Coins enum

        Returns :
            bool: True if allowed, false otherwise

        Raises:
            TypeError: If coin_idx is not of Bip44Coins enum
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetPurpose():
        """ Get purpose.

        Returns:
            int: Purpose index
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetCoinClass(coin_idx):
        """ Get coin class.

        Args:
            coin_idx (Bip44Coins): Coin index, must be a Bip44Coins enum

        Returns:
            BipCoinBase child object: BipCoinBase child object
        """
        pass
