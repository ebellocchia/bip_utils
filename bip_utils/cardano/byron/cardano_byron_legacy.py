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

"""Module for Cardano Byron legacy keys derivation."""


# Imports
from __future__ import annotations

from functools import lru_cache
from typing import Union

from bip_utils.addr import AdaByronAddrDecoder, AdaByronLegacyAddrEncoder
from bip_utils.bip.bip32 import Bip32Base, Bip32KeyIndex, Bip32Path, Bip32PrivateKey, Bip32PublicKey
from bip_utils.cardano.bip32 import CardanoByronLegacyBip32
from bip_utils.utils.crypto import Pbkdf2HmacSha512


class CardanoByronLegacyConst:
    """Class container for Cardano Byron legacy constants."""

    # PBKDF2 salt used for deriving the HD path key
    HD_PATH_KEY_PBKDF2_SALT: str = "address-hashing"
    # PBKDF2 rounds used for deriving the HD path key
    HD_PATH_KEY_PBKDF2_ROUNDS: int = 500
    # PBKDF2 output byte length used for deriving the HD path key
    HD_PATH_KEY_PBKDF2_OUT_BYTE_LEN: int = 32


class CardanoByronLegacy:
    """
    Cardano Byron legacy class.
    It allows master key generation, children keys derivation and addresses computation like the old Daedalus wallet.
    Addresses are in the Ddz... format, which contains the encrypted derivation path.
    """

    m_bip32_obj: Bip32Base

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> CardanoByronLegacy:
        """
        Construct class from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            CardanoByronLegacy object: CardanoByronLegacy object
        """
        return cls(CardanoByronLegacyBip32.FromSeed(seed_bytes))

    def __init__(self,
                 bip32_obj: Bip32Base) -> None:
        """
        Construct class.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object

        Raises:
            ValueError: If the bip32 object is not a master key
            TypeError: If the bip32 object is not a CardanoByronLegacyBip32 class instance
        """
        if not isinstance(bip32_obj, CardanoByronLegacyBip32):
            raise TypeError("The Bip32 object shall be a CardanoByronLegacyBip32 instance")
        if bip32_obj.Depth() != 0:
            raise ValueError("The Bip32 object shall be a master key (i.e. depth equal to 0)")
        self.m_bip32_obj = bip32_obj

    def Bip32Object(self) -> Bip32Base:
        """
        Return the BIP32 object.

        Returns:
            Bip32Base object: Bip32Base object
        """
        return self.m_bip32_obj

    @lru_cache()
    def HdPathKey(self) -> bytes:
        """
        Get the key used for HD path decryption/encryption.

        Returns:
            bytes: Key bytes
        """
        return Pbkdf2HmacSha512.DeriveKey(
            self.m_bip32_obj.PublicKey().RawCompressed().ToBytes()[1:] + self.m_bip32_obj.ChainCode().ToBytes(),
            CardanoByronLegacyConst.HD_PATH_KEY_PBKDF2_SALT,
            CardanoByronLegacyConst.HD_PATH_KEY_PBKDF2_ROUNDS,
            CardanoByronLegacyConst.HD_PATH_KEY_PBKDF2_OUT_BYTE_LEN
        )

    def HdPathFromAddress(self,
                          address: str) -> Bip32Path:
        """
        Get the HD path from an address by decrypting it.
        The address shall be derived from the current object master key (i.e. self.m_bip32_obj) in order to
        successfully decrypt the path.

        Args:
            address (str): Address string

        Returns:
            Bip32Path object: Bip32Path object

        Raises:
            ValueError: If the address encoding is not valid or the path cannot be decrypted
        """
        addr_dec_bytes = AdaByronAddrDecoder.DecodeAddr(address)
        hd_path_dec_bytes = AdaByronAddrDecoder.DecryptHdPath(AdaByronAddrDecoder.SplitDecodedBytes(addr_dec_bytes)[1],
                                                              self.HdPathKey())
        return hd_path_dec_bytes

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

    def GetPrivateKey(self,
                      first_idx: Union[int, Bip32KeyIndex],
                      second_idx: Union[int, Bip32KeyIndex]) -> Bip32PrivateKey:
        """
        Get the private key with the specified indexes.
        Derivation path: m/first_idx'/second_idx'
        The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').

        Args:
            first_idx (int or Bip32KeyIndex object) : First index
            second_idx (int or Bip32KeyIndex object): Second index

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(first_idx, second_idx).PrivateKey()

    def GetPublicKey(self,
                     first_idx: Union[int, Bip32KeyIndex],
                     second_idx: Union[int, Bip32KeyIndex]) -> Bip32PublicKey:
        """
        Get the public key with the specified indexes.
        Derivation path: m/first_idx'/second_idx'
        The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').


        Args:
            first_idx (int or Bip32KeyIndex object) : First index
            second_idx (int or Bip32KeyIndex object): Second index

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.__DeriveKey(first_idx, second_idx).PublicKey()

    @lru_cache()
    def GetAddress(self,
                   first_idx: Union[int, Bip32KeyIndex],
                   second_idx: Union[int, Bip32KeyIndex]) -> str:
        """
        Get the address with the specified indexes.
        Derivation path: m/first_idx'/second_idx'
        The indexes will be automatically hardened if not (e.g. 0, 1' -> 0', 1').

        Args:
            first_idx (int or Bip32KeyIndex object) : First index
            second_idx (int or Bip32KeyIndex object): Second index

        Returns:
            str: Address

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        pub_key = self.GetPublicKey(first_idx, second_idx)
        return AdaByronLegacyAddrEncoder.EncodeKey(
            pub_key.KeyObject(),
            chain_code=pub_key.ChainCode(),
            hd_path=self.__GetDerivationPath(first_idx, second_idx),
            hd_path_key=self.HdPathKey()
        )

    @lru_cache()
    def __DeriveKey(self,
                    first_idx: Union[int, Bip32KeyIndex],
                    second_idx: Union[int, Bip32KeyIndex]) -> Bip32Base:
        """
        Derive the key with the specified change and address indexes.
        Derivation path: m/first_idx'/second_idx'

        Args:
            first_idx (int or Bip32KeyIndex object) : First index
            second_idx (int or Bip32KeyIndex object): Second index

        Returns:
            Bip32Base object: Bip32Base object

        Raises:
            Bip32KeyError: If the derivation results in an invalid key
            Bip32PathError: If the path indexes are not valid
        """
        return self.m_bip32_obj.DerivePath(
            self.__GetDerivationPath(first_idx, second_idx)
        )

    @staticmethod
    def __GetDerivationPath(first_idx: Union[int, Bip32KeyIndex],
                            second_idx: Union[int, Bip32KeyIndex]) -> str:
        """
        Get the derivation path from the specified indexes.

        Args:
            first_idx (int or Bip32KeyIndex object) : First index
            second_idx (int or Bip32KeyIndex object): Second index

        Returns:
            str: Derivation path
        """
        return f"m/{first_idx}'/{second_idx}'"
