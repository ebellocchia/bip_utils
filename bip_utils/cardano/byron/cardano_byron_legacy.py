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
from typing import List, Union
import cbor2
from bip_utils.addr import AdaByronAddrEncoder
from bip_utils.bip.bip32 import Bip32Base, Bip32KeyIndex, Bip32PublicKey, Bip32PrivateKey, Bip32Utils
from bip_utils.cardano.bip32 import CardanoByronLegacyBip32
from bip_utils.utils.misc import CryptoUtils


class DaedalusLegacyConst:
    """Class container for Cardano Byron legacy constants."""

    # ChaCha20-Poly1305 nonce
    CHACHA20_POLY1305_NONCE: bytes = b"serokellfore"
    # ChaCha20-Poly1305 associated data
    CHACHA20_POLY1305_ASSOC_DATA: bytes = b""
    # PBKDF2 salt
    PBKDF2_SALT: str = "address-hashing"
    # PBKDF2 rounds
    PBKDF2_ROUNDS: int = 500
    # PBKDF2 output byte length
    PBKDF2_OUT_BYTE_LEN: int = 32


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
        return CryptoUtils.Pbkdf2HmacSha512(
            self.m_bip32_obj.PublicKey().RawCompressed().ToBytes()[1:] + self.m_bip32_obj.ChainCode().ToBytes(),
            DaedalusLegacyConst.PBKDF2_SALT,
            DaedalusLegacyConst.PBKDF2_ROUNDS,
            DaedalusLegacyConst.PBKDF2_OUT_BYTE_LEN
        )

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
        hd_path_enc_bytes = self.__EncryptHdPath(
            [int(idx.Harden()) if isinstance(idx, Bip32KeyIndex) else Bip32Utils.HardenIndex(idx)
             for idx in (first_idx, second_idx)]
        )

        return AdaByronAddrEncoder.EncodeKey(
            pub_key.KeyObject(),
            chain_code=pub_key.ChainCode(),
            hd_path_enc=hd_path_enc_bytes
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
        return self.m_bip32_obj.DerivePath(f"m/{first_idx}'/{second_idx}'")

    def __EncryptHdPath(self,
                        path_indexes: List[int]) -> bytes:
        """
        Encrypt the HD path.

        Args:
            path_indexes (list[int]): Path indexes

        Returns:
            bytes: Computed key bytes
        """
        cipher_text_bytes, tag_bytes = CryptoUtils.ChaCha20Poly1305Encrypt(
            key=self.HdPathKey(),
            nonce=DaedalusLegacyConst.CHACHA20_POLY1305_NONCE,
            assoc_data=DaedalusLegacyConst.CHACHA20_POLY1305_ASSOC_DATA,
            plain_text=self.__CborEncodeVarList(path_indexes)
        )
        return cipher_text_bytes + tag_bytes

    @staticmethod
    def __CborEncodeVarList(var_list: List[int]) -> bytes:
        """
        CBOR-encode the specified list of variables.

        Args:
            var_list (list[int]): List of variables

        Returns:
            bytes: CBOR-encoded list of variables
        """
        return b"\x9f" + b"".join([cbor2.dumps(p) for p in var_list]) + b"\xFF"
