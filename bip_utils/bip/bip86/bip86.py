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

"""
Module for BIP86 keys derivation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
"""

# Imports
from typing import Union
from bip_utils.bip.bip32 import Bip32Utils, Bip32ChainCode, Bip32Depth, Bip32FingerPrint, Bip32KeyIndex
from bip_utils.bip.bip44_base import Bip44Changes, Bip44Base
from bip_utils.bip.conf.bip86 import Bip86ConfGetter
from bip_utils.bip.conf.common import BipCoins
from bip_utils.ecc import IPrivateKey


class Bip86Const:
    """Class container for BIP86 constants."""

    # Specification name
    SPEC_NAME: str = "BIP-0086"
    # Purpose
    PURPOSE: int = Bip32Utils.HardenIndex(86)


class Bip86(Bip44Base):
    """
    BIP86 class.
    It allows master key generation and children keys derivation in according to BIP-0086.
    """

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 coin_type: BipCoins) -> Bip44Base:
        """
        Create a Bip object from the specified seed (e.g. BIP39 seed).
        The test net flag is automatically set when the coin is derived. However, if you want to get the correct master
        or purpose keys, you have to specify here if it's a test net.

        Args:
            seed_bytes (bytes)  : Seed bytes
            coin_type (BipCoins): Coin type, shall be a Bip86Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin type is not a Bip86Coins enum
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Bip86ConfGetter already checks the enum type
        return cls._FromSeed(seed_bytes,
                             Bip86ConfGetter.GetConfig(coin_type))

    @classmethod
    def FromExtendedKey(cls,
                        key_str: str,
                        coin_type: BipCoins) -> Bip44Base:
        """
        Create a Bip object from the specified extended key.

        Args:
            key_str (str)       : Extended key string
            coin_type (BipCoins): Coin type, shall be a Bip86Coins enum

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin type is not a Bip86Coins enum
            Bip32KeyError: If the extended key is not valid
        """

        # Bip86ConfGetter already checks the enum type
        return cls._FromExtendedKey(key_str,
                                    Bip86ConfGetter.GetConfig(coin_type))

    @classmethod
    def FromPrivateKey(cls,
                       priv_key: Union[bytes, IPrivateKey],
                       coin_type: BipCoins,
                       chain_code: Union[bytes, Bip32ChainCode] = Bip32ChainCode(),
                       depth: Union[int, Bip32Depth] = Bip32Depth(0),
                       index: Union[int, Bip32KeyIndex] = Bip32KeyIndex(0),
                       fprint: Union[bytes, Bip32FingerPrint] = Bip32FingerPrint()) -> Bip44Base:
        """
        Create a Bip object from the specified private key and derivation data.
        If only the private key bytes are specified, the key will be considered a master key with
        the chain code set to zero, since there is no way to recover the key derivation data.

        Args:
            priv_key (bytes or IPrivateKey)                      : Private key
            coin_type (BipCoins)                                 : Coin type, shall be a Bip86Coins enum
            chain_code (bytes or Bip32ChainCode object, optional): Chain code (default: all zeros)
            depth (int or Bip32Depth object, optional)           : Child depth (default: 0)
            index (int or Bip32KeyIndex object, optional)        : Child index (default: 0)
            fprint (bytes or Bip32FingerPrint object, optional)  : Parent fingerprint (default: master key)

        Returns:
            Bip object: Bip object

        Raises:
            TypeError: If coin type is not a Bip86Coins enum
            Bip32KeyError: If the key is not valid
        """

        # Bip86ConfGetter already checks the enum type
        return cls._FromPrivateKey(priv_key,
                                   Bip86ConfGetter.GetConfig(coin_type),
                                   chain_code,
                                   depth,
                                   index,
                                   fprint)

    #
    # Override methods
    #

    def DeriveDefaultPath(self) -> Bip44Base:
        """
        Derive a child key from the purpose and return a new Bip object.
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return self._DeriveDefaultPathGeneric(self, Bip86Const.PURPOSE)

    def Purpose(self) -> Bip44Base:
        """
        Derive a child key from the purpose and return a new Bip object.
        It calls the underlying _PurposeGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return self._PurposeGeneric(self, Bip86Const.PURPOSE)

    def Coin(self) -> Bip44Base:
        """
        Derive a child key from the coin type specified at construction and return a new Bip object.
        It calls the underlying _CoinGeneric method with the current object as parameter.

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return self._CoinGeneric(self)

    def Account(self,
                acc_idx: int) -> Bip44Base:
        """
        Derive a child key from the specified account index and return a new Bip object.
        It calls the underlying _AccountGeneric method with the current object as parameter.

        Args:
            acc_idx (int): Account index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return self._AccountGeneric(self, acc_idx)

    def Change(self,
               change_type: Bip44Changes) -> Bip44Base:
        """
        Derive a child key from the specified change type and return a new Bip object.
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
        return self._ChangeGeneric(self, change_type)

    def AddressIndex(self,
                     addr_idx: int) -> Bip44Base:
        """
        Derive a child key from the specified address index and return a new Bip object.
        It calls the underlying _AddressIndexGeneric method with the current object as parameter.

        Args:
            addr_idx (int): Address index

        Returns:
            Bip44Base object: Bip44Base object

        Raises:
            Bip44DepthError: If current depth is not suitable for deriving keys
            Bip32KeyError: If the derivation results in an invalid key
        """
        return self._AddressIndexGeneric(self, addr_idx)

    @staticmethod
    def SpecName() -> str:
        """
        Get specification name.

        Returns:
            str: Specification name
        """
        return Bip86Const.SPEC_NAME
