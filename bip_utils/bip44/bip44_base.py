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
from abc import ABC, abstractmethod
from enum import Enum, IntEnum, auto, unique
from functools import lru_cache
from typing import Dict, Type
from bip_utils.bip32 import (
    Bip32Base, Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip, Bip32Nist256p1, Bip32Secp256k1, Bip32Utils
)
from bip_utils.bip44.bip44_base_ex import Bip44DepthError, Bip44CoinNotAllowedError
from bip_utils.bip44.bip44_keys import Bip44PublicKey, Bip44PrivateKey
from bip_utils.conf import Bip32Types, BipCoinConf


@unique
class Bip44Coins(Enum):
    """ Enumerative for supported BIP44 coins.
    The indexes are just dummy values, they are converted to BIP44 indexes using the COIN_TO_IDX dictionary.
    """

    # Main nets
    ALGORAND = auto(),
    AVAX_C_CHAIN = auto(),
    AVAX_P_CHAIN = auto(),
    AVAX_X_CHAIN = auto(),
    BAND_PROTOCOL = auto(),
    BINANCE_CHAIN = auto(),
    BINANCE_SMART_CHAIN = auto(),
    BITCOIN = auto(),
    BITCOIN_CASH = auto(),
    BITCOIN_SV = auto(),
    COSMOS = auto(),
    DASH = auto(),
    DOGECOIN = auto(),
    ELROND = auto(),
    ETHEREUM = auto(),
    ETHEREUM_CLASSIC = auto(),
    FANTOM_OPERA = auto(),
    FILECOIN = auto(),
    HARMONY_ONE_ATOM = auto(),
    HARMONY_ONE_ETH = auto(),
    HARMONY_ONE_METAMASK = auto(),
    HUOBI_CHAIN = auto(),
    IRIS_NET = auto(),
    KAVA = auto(),
    KUSAMA_ED25519_SLIP = auto(),
    LITECOIN = auto(),
    NANO = auto(),
    NEO = auto(),
    NINE_CHRONICLES_GOLD = auto(),
    OKEX_CHAIN_ATOM = auto(),
    OKEX_CHAIN_ATOM_OLD = auto(),
    OKEX_CHAIN_ETH = auto(),
    ONTOLOGY = auto(),
    POLKADOT_ED25519_SLIP = auto(),
    POLYGON = auto(),
    RIPPLE = auto(),
    SOLANA = auto(),
    STELLAR = auto(),
    TERRA = auto(),
    TEZOS = auto(),
    THETA = auto(),
    TRON = auto(),
    VECHAIN = auto(),
    ZCASH = auto(),
    ZILLIQA = auto(),
    # Test nets
    BITCOIN_CASH_TESTNET = auto(),
    BITCOIN_SV_TESTNET = auto(),
    BITCOIN_TESTNET = auto(),
    DASH_TESTNET = auto(),
    DOGECOIN_TESTNET = auto(),
    LITECOIN_TESTNET = auto(),
    ZCASH_TESTNET = auto(),


@unique
class Bip44Changes(IntEnum):
    """ Enumerative for BIP44 changes. """

    CHAIN_EXT = 0,
    CHAIN_INT = 1,


@unique
class Bip44Levels(IntEnum):
    """ Enumerative for BIP44 levels. """

    MASTER = 0,
    PURPOSE = 1,
    COIN = 2,
    ACCOUNT = 3,
    CHANGE = 4,
    ADDRESS_INDEX = 5,


class Bip44BaseConst:
    """ Class container for BIP44 base constants. """

    # Map from coin to index
    COIN_TO_IDX: Dict[Bip44Coins, int] = {
            # Main nets
            Bip44Coins.BITCOIN: 0,
            Bip44Coins.LITECOIN: 2,
            Bip44Coins.DOGECOIN: 3,
            Bip44Coins.DASH: 5,
            Bip44Coins.ETHEREUM: 60,
            Bip44Coins.BINANCE_SMART_CHAIN: 60,
            Bip44Coins.AVAX_C_CHAIN: 60,
            Bip44Coins.POLYGON: 60,
            Bip44Coins.FANTOM_OPERA: 60,
            Bip44Coins.HUOBI_CHAIN: 60,
            Bip44Coins.HARMONY_ONE_METAMASK: 60,
            Bip44Coins.OKEX_CHAIN_ETH: 60,
            Bip44Coins.OKEX_CHAIN_ATOM: 60,
            Bip44Coins.ETHEREUM_CLASSIC: 61,
            Bip44Coins.COSMOS: 118,
            Bip44Coins.IRIS_NET: 118,
            Bip44Coins.ZCASH: 133,
            Bip44Coins.RIPPLE: 144,
            Bip44Coins.BITCOIN_CASH: 145,
            Bip44Coins.STELLAR: 148,
            Bip44Coins.NANO: 165,
            Bip44Coins.TRON: 195,
            Bip44Coins.BITCOIN_SV: 236,
            Bip44Coins.ALGORAND: 283,
            Bip44Coins.KUSAMA_ED25519_SLIP: 354,
            Bip44Coins.POLKADOT_ED25519_SLIP: 354,
            Bip44Coins.FILECOIN: 461,
            Bip44Coins.BAND_PROTOCOL: 494,
            Bip44Coins.KAVA: 494,
            Bip44Coins.ZILLIQA: 313,
            Bip44Coins.TERRA: 330,
            Bip44Coins.THETA: 500,
            Bip44Coins.SOLANA: 501,
            Bip44Coins.ELROND: 508,
            Bip44Coins.NINE_CHRONICLES_GOLD: 567,
            Bip44Coins.BINANCE_CHAIN: 714,
            Bip44Coins.VECHAIN: 818,
            Bip44Coins.NEO: 888,
            Bip44Coins.OKEX_CHAIN_ATOM_OLD: 996,
            Bip44Coins.HARMONY_ONE_ETH: 1023,
            Bip44Coins.HARMONY_ONE_ATOM: 1023,
            Bip44Coins.ONTOLOGY: 1024,
            Bip44Coins.TEZOS: 1729,
            Bip44Coins.AVAX_X_CHAIN: 9000,
            Bip44Coins.AVAX_P_CHAIN: 9000,
            # Test nets
            Bip44Coins.BITCOIN_CASH_TESTNET: 1,
            Bip44Coins.BITCOIN_SV_TESTNET: 1,
            Bip44Coins.BITCOIN_TESTNET: 1,
            Bip44Coins.DASH_TESTNET: 1,
            Bip44Coins.DOGECOIN_TESTNET: 1,
            Bip44Coins.LITECOIN_TESTNET: 1,
            Bip44Coins.ZCASH_TESTNET: 1,
        }

    # BIP32 type to class
    BIP32_TYPE_TO_CLASS: Dict[Bip32Types, Type[Bip32Base]] = {
        Bip32Types.ED25519_SLIP: Bip32Ed25519Slip,
        Bip32Types.ED25519_BLAKE2B_SLIP: Bip32Ed25519Blake2bSlip,
        Bip32Types.NIST256P1: Bip32Nist256p1,
        Bip32Types.SECP256K1: Bip32Secp256k1,
    }


class Bip44Base(ABC):
    """ BIP44 base class.
    It allows coin, account, chain and address keys generation in according to BIP44
    or its extension (e.g. BIP49, BIP84).
    The class is meant to be derived by classes implementing BIP44 or its extension.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 coin_type: Bip44Coins) -> Bip44Base:
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified seed (e.g. BIP39 seed).
        The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
        or purpose keys, you have to specify here if it's a test net.

        Args:
            seed_bytes (bytes)   : Seed bytes
            coin_type (Bip44Coins): Coin type, must be a Bip44Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin index is not a Bip44Coins enum
            ValueError: If the seed is too short
            Bip44CoinNotAllowedError: If the coin is not allowed to derive from the BIP specification
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        if not cls.IsCoinAllowed(coin_type):
            raise Bip44CoinNotAllowedError("Coin %s cannot derive from %s specification" % (coin_type, cls.SpecName()))

        coin_conf = cls._GetCoinConf(coin_type)
        bip32_cls = Bip44BaseConst.BIP32_TYPE_TO_CLASS[coin_conf.Bip32Type()]
        return cls(bip32_cls.FromSeed(seed_bytes,
                                      coin_conf.KeyNetVersions()),
                   coin_type)

    @classmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        coin_type: Bip44Coins) -> Bip44Base:
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified extended key.

        Args:
            key_str (str)        : Extended key string
            coin_type (Bip44Coins): Coin type, must be a Bip44Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin index is not a Bip44Coins enum
            Bip44CoinNotAllowedError: If the coin is not allowed to derive from the BIP specification
            Bip32KeyError: If the extended key is not valid
        """
        if not cls.IsCoinAllowed(coin_type):
            raise Bip44CoinNotAllowedError("Coin %s cannot derive from %s specification" % (coin_type, cls.SpecName()))

        coin_conf = cls._GetCoinConf(coin_type)
        bip32_cls = Bip44BaseConst.BIP32_TYPE_TO_CLASS[coin_conf.Bip32Type()]
        return cls(bip32_cls.FromExtendedKey(key_str,
                                             coin_conf.KeyNetVersions()),
                   coin_type)

    @classmethod
    def FromPrivateKey(cls,
                       key_bytes: bytes,
                       coin_type: Bip44Coins) -> Bip44Base:
        """ Create a Bip object (e.g. BIP44, BIP49, BIP84) from the specified private key.
        The key will be considered a master key with the chain code set to zero,
        since there is no way to recover the key derivation data.

        Args:
            key_bytes (bytes)     : Key bytes
            coin_type (Bip44Coins): Coin type, must be a Bip44Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin index is not a Bip44Coins enum
            Bip44CoinNotAllowedError: If the coin is not allowed to derive from the BIP specification
            Bip32KeyError: If the key is not valid
        """
        if not cls.IsCoinAllowed(coin_type):
            raise Bip44CoinNotAllowedError("Coin %s cannot derive from %s specification" % (coin_type, cls.SpecName()))

        coin_conf = cls._GetCoinConf(coin_type)
        bip32_cls = Bip44BaseConst.BIP32_TYPE_TO_CLASS[coin_conf.Bip32Type()]
        return cls(bip32_cls.FromPrivateKey(key_bytes,
                                            key_net_ver=coin_conf.KeyNetVersions()),
                   coin_type)

    #
    # Public methods
    #

    def __init__(self,
                 bip32_obj: Bip32Base,
                 coin_type: Bip44Coins) -> None:
        """ Construct class from a Bip32 object and coin type.

        Args:
            bip32_obj (Bip32 object): Bip32 object
            coin_type (Bip44Coins)  : Coin type, must be a Bip44Coins enum

        Returns:
            Bip44DepthError: If the Bip32 object depth is not valid
        """

        depth = bip32_obj.Depth()

        # If the Bip32 is public-only, the depth shall start from the account level because hardened derivation is
        # used below it, which is not possible with public keys
        if bip32_obj.IsPublicOnly():
            if depth < Bip44Levels.ACCOUNT or depth > Bip44Levels.ADDRESS_INDEX:
                raise Bip44DepthError(
                    "Depth of the public-only Bip32 object (%d) is below account level or beyond address index level" % depth)
        # If the Bip32 object is not public-only, any depth is fine as long as it is not greater
        # than address index level
        else:
            if depth > Bip44Levels.ADDRESS_INDEX:
                raise Bip44DepthError("Depth of the Bip32 object (%d) is beyond address index level" % depth)

        # Finally, initialize class
        self.m_bip32 = bip32_obj
        self.m_coin_type = coin_type
        self.m_coin_conf = self._GetCoinConf(coin_type)

    @lru_cache()
    def PublicKey(self) -> Bip44PublicKey:
        """ Return the public key.

        Returns:
            Bip44PublicKey object: Bip44PublicKey object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        return Bip44PublicKey(self.m_bip32.PublicKey(),
                              self.m_coin_conf)

    @lru_cache()
    def PrivateKey(self) -> Bip44PrivateKey:
        """ Return the private key.

        Returns:
            Bip44PrivateKey object: Bip44PrivateKey object

        Raises:
            Bip32KeyError: If the Bip32 object is public-only or the constructed key is not valid
        """
        return Bip44PrivateKey(self.m_bip32.PrivateKey(),
                               self.m_coin_conf)

    def CoinConf(self) -> BipCoinConf:
        """ Get coin configuration.

        Returns:
            BipCoinConf object: BipCoinConf object
        """
        return self.m_coin_conf

    def IsPublicOnly(self) -> bool:
        """ Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_bip32.IsPublicOnly()

    def IsLevel(self,
                level_idx: int) -> bool:
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
    def _DeriveDefaultPathGeneric(cls,
                                  bip_obj: Bip44Base) -> Bip44Base:
        """ Derive the default coin path and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.MASTER):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving purpose" % bip_obj.m_bip32.Depth().ToInt())

        # Derive purpose and coin by default
        bip_obj = cls._PurposeGeneric(bip_obj)
        bip_obj = cls._CoinGeneric(bip_obj)

        # Derive the remaining path
        return cls(bip_obj.m_bip32.DerivePath(bip_obj.m_coin_conf.DefaultPath()), bip_obj.m_coin_type)

    @classmethod
    def _PurposeGeneric(cls,
                        bip_obj: Bip44Base) -> Bip44Base:
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.MASTER):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving purpose" % bip_obj.m_bip32.Depth().ToInt())

        return cls(bip_obj.m_bip32.ChildKey(cls._GetPurpose()), bip_obj.m_coin_type)

    @classmethod
    def _CoinGeneric(cls,
                     bip_obj: Bip44Base) -> Bip44Base:
        """ Derive a child key from the coin type specified at construction and return
        a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.PURPOSE):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving coin" % bip_obj.m_bip32.Depth().ToInt())

        coin_idx = Bip44BaseConst.COIN_TO_IDX[bip_obj.m_coin_type]

        return cls(bip_obj.m_bip32.ChildKey(Bip32Utils.HardenIndex(coin_idx)), bip_obj.m_coin_type)

    @classmethod
    def _AccountGeneric(cls,
                        bip_obj: Bip44Base,
                        acc_idx: int) -> Bip44Base:
        """ Derive a child key from the specified account index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)
            acc_idx (int)             : Account index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.COIN):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving account" % bip_obj.m_bip32.Depth().ToInt())

        return cls(bip_obj.m_bip32.ChildKey(Bip32Utils.HardenIndex(acc_idx)), bip_obj.m_coin_type)

    @classmethod
    def _ChangeGeneric(cls,
                       bip_obj: Bip44Base,
                       change_type: Bip44Changes) -> Bip44Base:
        """ Derive a child key from the specified chain type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)
            change_type (Bip44Changes): Change type, must a Bip44Changes enum

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            TypeError: If chain index is not a Bip44Changes enum
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not isinstance(change_type, Bip44Changes):
            raise TypeError("Change index is not an enumerative of Bip44Changes")

        if not cls.IsLevel(bip_obj, Bip44Levels.ACCOUNT):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving change" % bip_obj.m_bip32.Depth().ToInt())

        # Use hardened derivation if not-hardended is not supported
        if not bip_obj.m_bip32.IsPrivateUnhardenedDerivationSupported():
            change_idx = Bip32Utils.HardenIndex(int(change_type))
        else:
            change_idx = int(change_type)

        return cls(bip_obj.m_bip32.ChildKey(change_idx), bip_obj.m_coin_type)

    @classmethod
    def _AddressIndexGeneric(cls,
                             bip_obj: Bip44Base,
                             addr_idx: int) -> Bip44Base:
        """ Derive a child key from the specified address index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It shall be called from a child class.

        Args:
            bip_obj (Bip44Base object): Bip44Base object (e.g. BIP44, BIP49, BIP84)
            addr_idx (int)            : Address index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        if not cls.IsLevel(bip_obj, Bip44Levels.CHANGE):
            raise Bip44DepthError("Current depth (%d) is not suitable for deriving address" % bip_obj.m_bip32.Depth().ToInt())

        # Use hardened derivation if not-hardended is not supported
        if not bip_obj.m_bip32.IsPrivateUnhardenedDerivationSupported():
            addr_idx = Bip32Utils.HardenIndex(addr_idx)

        return cls(bip_obj.m_bip32.ChildKey(addr_idx), bip_obj.m_coin_type)

    #
    # Abstract methods
    #

    @abstractmethod
    def DeriveDefaultPath(self) -> Bip44Base:
        """ Derive the default coin path and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _DeriveDefaultPathGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If the current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Purpose(self) -> Bip44Base:
        """ Derive a child key from the purpose and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Coin(self) -> Bip44Base:
        """ Derive a child key from the coin type specified at construction and return
        a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _CoinGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Account(self,
                acc_idx: int) -> Bip44Base:
        """ Derive a child key from the specified account index and return
        a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AccountGeneric method with the current object as parameter.

        Args:
            acc_idx (int): Account index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def Change(self,
               change_type: Bip44Changes) -> Bip44Base:
        """ Derive a child key from the specified change type and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _ChangeGeneric method with the current object as parameter.

        Args:
            change_type (Bip44Changes): Change type, must a Bip44Changes enum

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            TypeError: If chain index is not a Bip44Changes enum
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @abstractmethod
    def AddressIndex(self,
                     addr_idx: int) -> Bip44Base:
        """ Derive a child key from the specified address index and return a new Bip object (e.g. BIP44, BIP49, BIP84).
        It calls the underlying _AddressIndexGeneric method with the current object as parameter.

        Args:
            addr_idx (int): Address index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        pass

    @staticmethod
    @abstractmethod
    def SpecName() -> str:
        """ Get specification name.

        Returns:
            str: Specification name
        """
        pass

    @staticmethod
    @abstractmethod
    def IsCoinAllowed(coin_type: Bip44Coins) -> bool:
        """ Get if the specified coin is allowed.

        Args:
            coin_type (Bip44Coins): Coin type, must be a Bip44Coins enum

        Returns :
            bool: True if allowed, false otherwise

        Raises:
            TypeError: If coin_type is not of Bip44Coins enum
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetPurpose() -> int:
        """ Get purpose.

        Returns:
            int: Purpose index
        """
        pass

    @staticmethod
    @abstractmethod
    def _GetCoinConf(coin_type: Bip44Coins) -> BipCoinConf:
        """ Get coin configuration.

        Args:
            coin_type (Bip44Coins): Coin type, must be a Bip44Coins enum

        Returns:
            BipCoinConf object: BipCoinConf object
        """
        pass
