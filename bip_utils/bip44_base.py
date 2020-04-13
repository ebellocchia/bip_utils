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
from .bip32 import Bip32
from .wif   import WifEncoder


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
class Bip44PrivKeyTypes(IntEnum):
    """ Enumerative for private key types. """

    EXT_KEY = 0,
    RAW_KEY = 1,


@unique
class Bip44PubKeyTypes(IntEnum):
    """ Enumerative for public key types. """

    EXT_KEY         = 0,
    RAW_UNCOMPR_KEY = 1,
    RAW_COMPR_KEY   = 2,


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
    # Change depth
    CHANGE_DEPTH        = 4
    # Address depth
    ADDRESS_INDEX_DEPTH = 5

    # Test net coin index
    TEST_NET_COIN_IDX   = 1

    # Map test net coins to main net coins
    TESTNET_TO_MAINNET_COINS = \
        {
            Bip44Coins.BITCOIN_TESTNET  : Bip44Coins.BITCOIN,
            Bip44Coins.LITECOIN_TESTNET : Bip44Coins.LITECOIN,
            Bip44Coins.DOGECOIN_TESTNET : Bip44Coins.DOGECOIN,
            Bip44Coins.DASH_TESTNET     : Bip44Coins.DASH,
        }


class Bip44DepthError(Exception):
    """ Expcetion in case of derivation from wrong depth. """
    pass


class Bip44Base(ABC):
    """ BIP44 base class.
    It allows coin, account, chain and address keys generation in according to BIP44 or its extension (e.g. BIP49, BIP84).
    The class is meant to be derived by classes implementing BIP44 or its extension.
    """

    def __init__(self, bip32_obj, coin_idx):
        """ Construct class from a Bip32 object and coin type.
        ValueError is raised if coin is not allowed to derive from current specification.
        Bip44DepthError is raised if the Bip32 object depth is not valid.

        Args:
            bip32_obj (Bip32 object) : Bip32 object
            coin_idx (Bip44Coins)    : coin index, must be a Bip44Coins enum
        """

        # Check if coin is allowed
        if not self.IsCoinAllowed(coin_idx):
            raise ValueError("Coin %s cannot derive from %s specification" % (coin_idx, self.SpecName()))

        # If the Bip32 is public-only, the depth shall start from the account level because hardened derivation is
        # used below it, which is not possible with public keys
        if bip32_obj.IsPublicOnly():
            if bip32_obj.Depth() < Bip44BaseConst.ACCOUNT_DEPTH or \
               bip32_obj.Depth() > Bip44BaseConst.ADDRESS_INDEX_DEPTH:
                raise Bip44DepthError("Depth of the public-only Bip32 object (%d) is below account level or beyond address index level" % bip32_obj.Depth())
        # If the Bip32 object is not public-only, any depth is fine as long as it is not greater than address index level
        else:
            if bip32_obj.Depth() > Bip44BaseConst.ADDRESS_INDEX_DEPTH:
                raise Bip44DepthError("Depth of the Bip32 object (%d) is beyond address index level" % bip32_obj.Depth())

        # Finally, initialize class
        self.m_bip32    = bip32_obj
        self.m_coin_idx = coin_idx

    @classmethod
    def FromSeed(cls, seed_bytes, coin_idx):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified seed (e.g. BIP39 seed).
        The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
        or purpose keys, you have to specify here if it's a test net.
        TypeError is raised if coin type is not a Bip44Coins enum.
        ValueError is raised (by Bip32) if the seed is too short.
        Bip32KeyError is raised (by Bip32) if the seed is not suitable for master key generation.

        Args:
            seed_bytes (bytes)    : seed bytes
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (Bip object):
            Bip object
        """

        # Check if test net
        if coin_idx in Bip44BaseConst.TESTNET_TO_MAINNET_COINS:
            coin_idx = Bip44BaseConst.TESTNET_TO_MAINNET_COINS[coin_idx]
            is_testnet = True
        else:
            is_testnet = False

        return cls(Bip32.FromSeed(seed_bytes, is_testnet), coin_idx)

    @classmethod
    def FromExtendedKey(cls, key_str, coin_idx):
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified extended key.
        Bip32KeyError is raised (by Bip32) if the key is not valid.

        Args:
            key_str (str)         : extended key string
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (Bip object):
            Bip object
        """

        # Check if test net
        if coin_idx in Bip44BaseConst.TESTNET_TO_MAINNET_COINS:
            coin_idx = Bip44BaseConst.TESTNET_TO_MAINNET_COINS[coin_idx]
            is_testnet = True
        else:
            is_testnet = False

        # Get net versions
        main_net_ver = cls._GetMainNetVersions(coin_idx)
        test_net_ver = cls._GetTestNetVersions(coin_idx)

        return cls(Bip32.FromExtendedKey(key_str, is_testnet, main_net_ver, test_net_ver), coin_idx)

    def PublicKey(self, key_type = Bip44PubKeyTypes.EXT_KEY):
        """ Return the public key.
        TypeError is raised if key_type is not of a Bip44PubKeyTypes enum.

        Args:
            extended (bool) : if true, the extended key encoded in base58 will be returned, oitherwise the key bytes

        Returns (str):
            Public key
        """

        if not isinstance(key_type, Bip44PubKeyTypes):
            raise TypeError("Key type is not an enumerative of Bip44PubKeyTypes")

        if key_type == Bip44PubKeyTypes.EXT_KEY:
            # Get versions
            main_pub_net_ver = self._GetMainNetVersions(self.m_coin_idx)["pub"]
            test_pub_net_ver = self._GetTestNetVersions(self.m_coin_idx)["pub"]
            # Get extended key
            return self.m_bip32.ExtendedPublicKey(main_pub_net_ver, test_pub_net_ver)
        else:
            return self.m_bip32.PublicKeyBytes(key_type == Bip44PubKeyTypes.RAW_COMPR_KEY)

    def PrivateKey(self, key_type = Bip44PrivKeyTypes.EXT_KEY):
        """ Return the private key.
        TypeError is raised if key_type is not of a Bip44PrivKeyTypes enum.
        Bip32KeyError is raised (by Bip32) if internal key is public-only.

        Args:
            key_type (Bip44PrivKeyTypes) : private key type

        Returns (str):
            Private key
        """

        if not isinstance(key_type, Bip44PrivKeyTypes):
            raise TypeError("Key type is not an enumerative of Bip44PrivKeyTypes")

        if key_type == Bip44PrivKeyTypes.EXT_KEY:
            # Get versions
            main_pub_net_ver = self._GetMainNetVersions(self.m_coin_idx)["priv"]
            test_pub_net_ver = self._GetTestNetVersions(self.m_coin_idx)["priv"]
            # Get extended key
            return self.m_bip32.ExtendedPrivateKey(main_pub_net_ver, test_pub_net_ver)
        else:
            return self.m_bip32.PrivateKeyBytes()

    def Address(self):
        """ Return address related to the current public key.

        Returns (str):
            Address string
        """
        addr_fct = self._GetComputeAddressFct(self.m_coin_idx)
        return addr_fct(self.m_bip32.PublicKey(), self.m_bip32.IsTestNet())

    def WalletImportFormat(self):
        """ Return the current private key encoded in WIF.

        Returns (str):
            Address string, empty if the coin does not support WIF
        """
        wif_net_ver = self._GetWifNetVersions(self.m_coin_idx)

        if not wif_net_ver is None:
            return WifEncoder.Encode(self.m_bip32.PrivateKeyBytes(), wif_net_ver["main"] if not self.m_bip32.IsTestNet() else wif_net_ver["test"])
        else:
            return ""

    def CoinNames(self):
        """ Get coin names.

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        return self._GetCoinNames(self.m_coin_idx)

    def IsPublicOnly(self):
        """ Get if it's public-only.

        Returns (bool):
            True if public-only, false otherwise
        """
        return self.m_bip32.IsPublicOnly()

    def IsTestNet(self):
        """ Return if it's a test net.

        Returns (bool):
            True if test net, false otherwise
        """
        return self.m_bip32.IsTestNet()

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
        return self.m_bip32.Depth() == Bip44BaseConst.CHANGE_DEPTH

    def IsAddressIndexLevel(self):
        """ Return if it's a address index path.

        Returns (bool):
            True if address index path, false otherwise
        """
        return self.m_bip32.Depth() == Bip44BaseConst.ADDRESS_INDEX_DEPTH

    @abstractmethod
    def Purpose(self):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _PurposeGeneric method with the current object as parameter.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the purpose results in an invalid key.

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Coin(self):
        """ Derive a child key from the coin type specified at construction and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _CoinGeneric method with the current object as parameter.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the purpose results in an invalid key.

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Account(self, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _AccountGeneric method with the current object as parameter.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the purpose results in an invalid key.

        Args:
            acc_idx (int) : account index

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def Change(self, change_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _ChangeGeneric method with the current object as parameter.
        TypeError is raised if chain type is not a Bip44Changes enum.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the change results in an invalid key.

        Args:
            change_idx (Bip44Changes) : change index, must a Bip44Changes enum

        Returns (Bip object):
            Bip object
        """
        pass

    @abstractmethod
    def AddressIndex(self, addr_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall call the underlying _AddressIndexGeneric method with the current object as parameter.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the change results in an invalid key.

        Args:
            addr_idx (int) : address index

        Returns (Bip object):
            Bip object
        """
        pass

    @staticmethod
    @abstractmethod
    def SpecName():
        """ Get specification name

        Returns (str):
            Specification name
        """
        pass

    @staticmethod
    @abstractmethod
    def IsCoinAllowed(coin_idx):
        """ Get if the specified coin is allowed.
        TypeError is raised if coin_idx is not of Bip44Coins enum.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (bool):
            True if allowed, false otherwise
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
    def _GetMainNetVersions(coin_idx):
        """ Get main net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            Main net versions (public at key "pub", private at key "priv")
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetTestNetVersions(coin_idx):
        """ Get test net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            Test net versions (public at key "pub", private at key "priv")
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetComputeAddressFct(coin_idx):
        """ Compute compute address function.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (function):
            Compute address function
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetWifNetVersions(coin_idx):
        """ Get WIF net versions.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict or None):
            WIF net versions (main net at key "main", test net at key "test"), None if not supported
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetCoinNames(coin_idx):
        """ Get coin names.

        Args:
            coin_idx (Bip44Coins) : coin index, must be a Bip44Coins enum

        Returns (dict):
            Coin names (name at key "name", abbreviation at key "abbr")
        """
        pass

    @classmethod
    def _PurposeGeneric(cls, bip_obj):
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the purpose results in an invalid key.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)       : address index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsMasterLevel(bip_obj):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving purpose" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(cls._GetPurpose()), bip_obj.m_coin_idx)

    @classmethod
    def _CoinGeneric(cls, bip_obj):
        """ Derive a child key from the coin type specified at construction and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the coin results in an invalid key.

        Args:
            bip_obj (BIP object)  : Bip object (e.g. BIP44, BIP49, BIP84)

        Returns (Bip object):
            Bip object
        """
        if not cls.IsPurposeLevel(bip_obj):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving coin" % bip_obj.m_bip32.Depth())

        coin_idx = Bip44BaseConst.TEST_NET_COIN_IDX if bip_obj.m_bip32.IsTestNet() else bip_obj.m_coin_idx

        return cls(bip_obj.m_bip32.ChildKey(Bip32.HardenIndex(coin_idx)), bip_obj.m_coin_idx)

    @classmethod
    def _AccountGeneric(cls, bip_obj, acc_idx):
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the account results in an invalid key.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            acc_idx (int)        : account index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsCoinLevel(bip_obj):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving account" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(Bip32.HardenIndex(acc_idx)), bip_obj.m_coin_idx)

    @classmethod
    def _ChangeGeneric(cls, bip_obj, change_idx):
        """ Derive a child key from the specified chain type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        TypeError is raised if chain type is not a Bip44Changes enum.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the change results in an invalid key.

        Args:
            bip_obj (BIP object)      : Bip object (e.g. BIP44, BIP49, BIP84)
            change_idx (Bip44Changes) : change index, must a Bip44Changes enum

        Returns (Bip object):
            Bip object
        """
        if not isinstance(change_idx, Bip44Changes):
            raise TypeError("Change index is not an enumerative of Bip44Changes")

        if not cls.IsAccountLevel(bip_obj):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving change" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(change_idx), bip_obj.m_coin_idx)

    @classmethod
    def _AddressIndexGeneric(cls, bip_obj, addr_idx):
        """ Derive a child key from the specified address index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.
        Bip44DepthError is raised is chain depth is not suitable for deriving keys.
        Bip32KeyError is raised (by Bip32) if the address index results in an invalid key.

        Args:
            bip_obj (BIP object) : Bip object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)       : address index

        Returns (Bip object):
            Bip object
        """
        if not cls.IsChangeLevel(bip_obj):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving address" % bip_obj.m_bip32.Depth())

        return cls(bip_obj.m_bip32.ChildKey(addr_idx), bip_obj.m_coin_idx)
