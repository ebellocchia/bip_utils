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

"""Module containing utility classes for Electrum v1 keys derivation, since it uses its own algorithm."""

# Imports
from __future__ import annotations

from functools import lru_cache
from typing import Optional, Union

from bip_utils.addr import P2PKHAddr, P2PKHPubKeyModes
from bip_utils.bip.bip32 import Bip32KeyIndex
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPrivateKey, IPublicKey, Secp256k1, Secp256k1PrivateKey, Secp256k1PublicKey
from bip_utils.utils.crypto import DoubleSha256
from bip_utils.utils.misc import AlgoUtils, BytesUtils, IntegerUtils


class ElectrumV1:
    """
    Electrum v1 class.
    It derives keys like the Electrum wallet with old (v1) mnemonic.
    """

    m_priv_key: Optional[IPrivateKey]
    m_pub_key: IPublicKey

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> ElectrumV1:
        """
        Construct class from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            ElectrumV1 object: ElectrumV1 object
        """

        # The seed is the private key itself
        return cls.FromPrivateKey(seed_bytes)

    @classmethod
    def FromPrivateKey(cls,
                       priv_key: Union[bytes, IPrivateKey]) -> ElectrumV1:
        """
        Construct class from private key.

        Args:
            priv_key (bytes or IPrivateKey): Private key

        Returns:
            ElectrumV1 object: ElectrumV1 object

        Raises:
            TypeError: if the private key is not a Secp256k1PrivateKey
        """
        if isinstance(priv_key, bytes):
            priv_key = Secp256k1PrivateKey.FromBytes(priv_key)
        return cls(priv_key, None)

    @classmethod
    def FromPublicKey(cls,
                      pub_key: Union[bytes, IPublicKey]) -> ElectrumV1:
        """
        Construct class from public key.

        Args:
            pub_key (bytes or IPublicKey): Public key

        Returns:
            ElectrumV1 object: ElectrumV1 object

        Raises:
            TypeError: if the public key is not a Secp256k1PublicKey
        """
        if isinstance(pub_key, bytes):
            pub_key = Secp256k1PublicKey.FromBytes(pub_key)
        return cls(None, pub_key)

    def __init__(self,
                 priv_key: Optional[IPrivateKey],
                 pub_key: Optional[IPublicKey]) -> None:
        """
        Construct class.

        Args:
            priv_key (IPrivateKey object, optional): Private key (None for a public-only object)
            pub_key (IPublicKey object, optional)  : Public key (only needed for a public-only object)
                                                     If priv_key is not None, it'll be discarded

        Raises:
            TypeError: if the private key is not a Secp256k1PrivateKey or the public key is not a Secp256k1PublicKey
        """
        if priv_key is not None:
            if not isinstance(priv_key, Secp256k1PrivateKey):
                raise TypeError("Private key shall be a secp256k1 key")

            self.m_priv_key = priv_key
            self.m_pub_key = priv_key.PublicKey()
        else:
            if not isinstance(pub_key, Secp256k1PublicKey):
                raise TypeError("Public key shall be a secp256k1 key")

            self.m_priv_key = None
            self.m_pub_key = pub_key

    def IsPublicOnly(self) -> bool:
        """
        Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_priv_key is None

    def MasterPrivateKey(self) -> IPrivateKey:
        """
        Get the master private key.

        Returns:
            IPrivateKey object: IPrivateKey object
        """
        if self.IsPublicOnly():
            raise ValueError("Public-only deterministic keys have no private half")

        assert isinstance(self.m_priv_key, Secp256k1PrivateKey)
        return self.m_priv_key

    def MasterPublicKey(self) -> IPublicKey:
        """
        Get the master public key.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return self.m_pub_key

    def GetPrivateKey(self,
                      change_idx: int,
                      addr_idx: int) -> IPrivateKey:
        """
        Get the private key with the specified change and address indexes.
        Derivation path (not BIP32 derivation): m/change_idx/addr_idx

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            ValueError: If one of the index is not valid
        """
        if self.IsPublicOnly():
            raise ValueError("Public-only deterministic keys have no private half")
        return self.__DerivePrivateKey(change_idx, addr_idx)

    def GetPublicKey(self,
                     change_idx: int,
                     addr_idx: int) -> IPublicKey:
        """
        Get the public key with the specified change and address indexes.
        Derivation path (not BIP32 derivation): m/change_idx/addr_idx

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index


        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            ValueError: If one of the index is not valid
        """
        return (self.__DerivePublicKey(change_idx, addr_idx)
                if self.IsPublicOnly()
                else self.GetPrivateKey(change_idx, addr_idx).PublicKey())

    @lru_cache()
    def GetAddress(self,
                   change_idx: int,
                   addr_idx: int) -> str:
        """
        Get the address with the specified change and address indexes.
        Derivation path (not BIP32 derivation): m/change_idx/addr_idx

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            str: Address

        Raises:
            ValueError: If one of the index is not valid
        """
        return P2PKHAddr.EncodeKey(self.GetPublicKey(change_idx, addr_idx),
                                   net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
                                   pub_key_mode=P2PKHPubKeyModes.UNCOMPRESSED)

    @lru_cache()
    def __DerivePrivateKey(self,
                           change_idx: int,
                           addr_idx: int) -> IPrivateKey:
        """
        Derive the private key with the specified change and address indexes.
        Derivation path (not BIP32 derivation): m/change_idx/addr_idx

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            IPrivateKey object: IPrivateKey object

        Raises:
            ValueError: If one of the index is not valid
        """
        self.__ValidateIndexes(change_idx, addr_idx)

        seq_bytes = self.__GetSequence(change_idx, addr_idx)
        priv_key_int = (self.MasterPrivateKey().Raw().ToInt() + BytesUtils.ToInteger(seq_bytes)) % Secp256k1.Order()
        return Secp256k1PrivateKey.FromBytes(
            IntegerUtils.ToBytes(priv_key_int, Secp256k1PrivateKey.Length())
        )

    @lru_cache()
    def __DerivePublicKey(self,
                          change_idx: int,
                          addr_idx: int) -> IPublicKey:
        """
        Derive the public key with the specified change and address indexes.
        Derivation path (not BIP32 derivation): m/change_idx/addr_idx

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            IPublicKey object: IPublicKey object

        Raises:
            ValueError: If one of the index is not valid
        """
        self.__ValidateIndexes(change_idx, addr_idx)

        seq_bytes = self.__GetSequence(change_idx, addr_idx)
        return Secp256k1PublicKey.FromPoint(
            self.MasterPublicKey().Point() + BytesUtils.ToInteger(seq_bytes) * Secp256k1.Generator()
        )

    def __GetSequence(self,
                      change_idx: int,
                      addr_idx: int) -> bytes:
        """
        Get sequence.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            bytes: Sequence bytes
        """
        return DoubleSha256.QuickDigest(
            AlgoUtils.Encode(f"{addr_idx}:{change_idx}:") + self.MasterPublicKey().RawUncompressed().ToBytes()[1:])

    @staticmethod
    def __ValidateIndexes(change_idx: int,
                          addr_idx: int) -> None:
        """
        Validate indexes and raise a ValueError if not valid.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Raises:
            ValueError: If one of the index is not valid
        """

        # Just try to create a key index object
        Bip32KeyIndex(change_idx)
        Bip32KeyIndex(addr_idx)
