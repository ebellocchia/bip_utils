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
from bip_utils.addr import P2PKHPubKeyModes, P2PKHAddr
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey, IPrivateKey, Secp256k1, Secp256k1PrivateKey
from bip_utils.utils.misc import AlgoUtils, BytesUtils, CryptoUtils, IntegerUtils


class ElectrumV1:
    """
    Electrum v1 class.
    It derives keys like the Electrum wallet with old (v1) mnemonic.
    """

    m_priv_key: IPrivateKey

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> ElectrumV1:
        """
        Construct class from seed bytes.
        This method is not strictly needed but it's kept to have the same usage of the *ElectrumV2Base* class.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            ElectrumV1 object: ElectrumV1 object
        """
        return cls(seed_bytes)

    def __init__(self,
                 seed_bytes: bytes) -> None:
        """
        Construct class.

        Args:
            seed_bytes (bytes): Seed bytes
        """
        self.m_priv_key = Secp256k1PrivateKey.FromBytes(seed_bytes)

    def MasterPrivateKey(self) -> IPrivateKey:
        """
        Get the master private key.

        Returns:
            IPrivateKey object: IPrivateKey object
        """
        return self.m_priv_key

    def MasterPublicKey(self) -> IPublicKey:
        """
        Get the master public key.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return self.m_priv_key.PublicKey()

    def GetPrivateKey(self,
                      change_idx: int,
                      addr_idx: int) -> IPrivateKey:
        """
        Get the private key with the specified change and address indexes.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            IPrivateKey object: IPrivateKey object
        """
        return self.__DeriveKey(change_idx, addr_idx)

    def GetPublicKey(self,
                     change_idx: int,
                     addr_idx: int) -> IPublicKey:
        """
        Get the public key with the specified change and address indexes.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            IPublicKey object: IPublicKey object
        """
        return self.GetPrivateKey(change_idx, addr_idx).PublicKey()

    def GetAddress(self,
                   change_idx: int,
                   addr_idx: int) -> str:
        """
        Get the address with the specified change and address indexes.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            str: Address
        """
        return P2PKHAddr.EncodeKey(self.GetPublicKey(change_idx, addr_idx),
                                   net_ver=CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver"),
                                   pub_key_mode=P2PKHPubKeyModes.UNCOMPRESSED)

    @lru_cache()
    def __DeriveKey(self,
                    change_idx: int,
                    addr_idx: int) -> IPrivateKey:
        """
        Derive the key with the specified change and address indexes.

        Args:
            change_idx (int): Change index
            addr_idx (int)  : Address index

        Returns:
            Bip32Base object: Bip32Base object
        """
        seq_bytes = self.__GetSequence(change_idx, addr_idx)
        priv_key_int = (self.MasterPrivateKey().Raw().ToInt() + BytesUtils.ToInteger(seq_bytes)) % Secp256k1.Order()
        return Secp256k1PrivateKey.FromBytes(
            IntegerUtils.ToBytes(priv_key_int, Secp256k1PrivateKey.Length())
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
        return CryptoUtils.DoubleSha256(
            AlgoUtils.Encode(f"{addr_idx}:{change_idx}:") + self.MasterPublicKey().RawUncompressed().ToBytes()[1:]
        )
