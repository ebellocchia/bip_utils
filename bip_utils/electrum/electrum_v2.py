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

"""Module containing utility classes for Electrum v2 keys derivation, since it uses its own paths."""

# Imports
from __future__ import annotations

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Union

from bip_utils.addr import P2PKHAddr, P2WPKHAddr
from bip_utils.bip.bip32 import Bip32Base, Bip32KeyIndex, Bip32PrivateKey, Bip32PublicKey, Bip32Slip10Secp256k1
from bip_utils.coin_conf import CoinsConf


class ElectrumV2Base(ABC):
    """Electrum v2 base class."""

    m_bip32_obj: Bip32Base

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> ElectrumV2Base:
        """
        Construct class from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            ElectrumV2Base object: ElectrumV2Base object
        """
        return cls(Bip32Slip10Secp256k1.FromSeed(seed_bytes))

    def __init__(self,
                 bip32_obj: Bip32Base) -> None:
        """
        Construct class.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object (shall be a Bip32Slip10Secp256k1 instance)

        Raises:
            TypeError: If the bip32 object is not a Bip32Slip10Secp256k1 class instance
            ValueError: If the bip32 object is not a master key
        """
        if not isinstance(bip32_obj, Bip32Slip10Secp256k1):
            raise TypeError("A Bip32Slip10Secp256k1 class instance is required")
        if bip32_obj.Depth() > 0:
            raise ValueError("The Bip32 object shall be a master key (i.e. depth equal to 0)")
        self.m_bip32_obj = bip32_obj

    def Bip32Object(self) -> Bip32Base:
        """
        Return the BIP32 object.

        Returns:
            Bip32Base object: Bip32Base object
        """
        return self.m_bip32_obj

    def IsPublicOnly(self) -> bool:
        """
        Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_bip32_obj.IsPublicOnly()

    def MasterPrivateKey(self) -> Bip32PrivateKey:
        """
        Get the master private key.

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object
        """
        return self.m_bip32_obj.PrivateKey()

    def MasterPublicKey(self) -> Bip32PublicKey:
        """
        Get the master public key.

        Returns:
            Bip32PublicKey object: Bip32PublicKey object
        """
        return self.m_bip32_obj.PublicKey()

    @abstractmethod
    def GetPrivateKey(self,
                      change_idx: Union[int, Bip32KeyIndex],
                      addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PrivateKey:
        """
        Get the private key with the specified change and address indexes.

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key or the object is public-only
            Bip32PathError: If the path indexes are not valid
        """

    @abstractmethod
    def GetPublicKey(self,
                     change_idx: Union[int, Bip32KeyIndex],
                     addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PublicKey:
        """
        Get the public key with the specified change and address indexes.

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PublicKey object: Bip32PublicKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """

    @abstractmethod
    def GetAddress(self,
                   change_idx: Union[int, Bip32KeyIndex],
                   addr_idx: Union[int, Bip32KeyIndex]) -> str:
        """
        Get the address with the specified change and address indexes.

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            str: Address

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """


class ElectrumV2Standard(ElectrumV2Base):
    """
    Electrum v2 standard class.
    It derives keys like the Electrum wallet with standard mnemonic.
    """

    def GetPrivateKey(self,
                      change_idx: Union[int, Bip32KeyIndex],
                      addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PrivateKey:
        """
        Get the private key with the specified change and address indexes.
        Derivation path: m/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key or the object is public-only
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(change_idx, addr_idx).PrivateKey()

    def GetPublicKey(self,
                     change_idx: Union[int, Bip32KeyIndex],
                     addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PublicKey:
        """
        Get the public key with the specified change and address indexes.
        Derivation path: m/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PublicKey object: Bip32PublicKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(change_idx, addr_idx).PublicKey()

    @lru_cache()
    def GetAddress(self,
                   change_idx: Union[int, Bip32KeyIndex],
                   addr_idx: Union[int, Bip32KeyIndex]) -> str:
        """
        Get the address with the specified change and address indexes.
        Derivation path: m/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            str: Address

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return P2PKHAddr.EncodeKey(self.GetPublicKey(change_idx, addr_idx).KeyObject(),
                                   net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"))

    @lru_cache()
    def __DeriveKey(self,
                    change_idx: Union[int, Bip32KeyIndex],
                    addr_idx: Union[int, Bip32KeyIndex]) -> Bip32Base:
        """
        Derive the key with the specified change and address indexes.
        Derivation path: m/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.m_bip32_obj.DerivePath(f"m/{change_idx}/{addr_idx}")


class ElectrumV2Segwit(ElectrumV2Base):
    """
    Electrum v2 segwit class.
    It derives keys like the Electrum wallet with segwit mnemonic.
    """

    m_bip32_acc: Bip32Base

    def __init__(self,
                 bip32: Bip32Base) -> None:
        """
        Construct class.

        Args:
            bip32 (Bip32Base object): Bip32Base object
        """
        super().__init__(bip32)
        self.m_bip32_acc = bip32.DerivePath("m/0'")

    def GetPrivateKey(self,
                      change_idx: Union[int, Bip32KeyIndex],
                      addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PrivateKey:
        """
        Get the private key with the specified change and address indexes.
        Derivation path: m/0'/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PrivateKey object: Bip32PrivateKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key or the object is public-only
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(change_idx, addr_idx).PrivateKey()

    def GetPublicKey(self,
                     change_idx: Union[int, Bip32KeyIndex],
                     addr_idx: Union[int, Bip32KeyIndex]) -> Bip32PublicKey:
        """
        Get the public key with the specified change and address indexes.
        Derivation path: m/0'/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32PublicKey object: Bip32PublicKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(change_idx, addr_idx).PublicKey()

    @lru_cache()
    def GetAddress(self,
                   change_idx: Union[int, Bip32KeyIndex],
                   addr_idx: Union[int, Bip32KeyIndex]) -> str:
        """
        Get the address with the specified change and address indexes.
        Derivation path: m/0'/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            str: Address

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return P2WPKHAddr.EncodeKey(self.GetPublicKey(change_idx, addr_idx).KeyObject(),
                                    hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"))

    @lru_cache()
    def __DeriveKey(self,
                    change_idx: Union[int, Bip32KeyIndex],
                    addr_idx: Union[int, Bip32KeyIndex]) -> Bip32Base:
        """
        Derive the key with the specified change and address indexes.
        Derivation path: m/0'/change_idx/addr_idx

        Args:
            change_idx (int or Bip32KeyIndex object): Change index
            addr_idx (int or Bip32KeyIndex object)  : Address index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.m_bip32_acc.DerivePath(f"{change_idx}/{addr_idx}")
