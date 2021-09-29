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
from functools import lru_cache
from typing import Optional, Union
from bip_utils.addr import XmrAddr
from bip_utils.ecc import Ed25519Monero, Ed25519MoneroPrivateKey, IPrivateKey, IPublicKey
from bip_utils.monero.monero_ex import MoneroKeyError
from bip_utils.monero.monero_keys import MoneroPrivateKey, MoneroPublicKey
from bip_utils.utils import ConvUtils, CryptoUtils


class MoneroConst:
    """ Class container for Monero keys constants. """

    # Address main net version
    ADDR_MAIN_NET_VER: bytes = b"\x12"
    # Address checksum length in bytes
    ADDR_CHECKSUM_BYTE_LEN: int = 4

    # Subaddress main net version
    SUBADDR_MAIN_NET_VER: bytes = b"\x2a"
    # Subaddress prefix
    SUBADDR_PREFIX: bytes = b"SubAddr\x00"
    # Subaddress maximum index
    SUBADDR_MAX_IDX: int = 2**32 - 1
    # Subaddress index length in byte
    SUBADDR_IDX_BYTE_LEN: int = 4


class MoneroUtils:
    """ Class container for Monero utility functions. """

    @staticmethod
    def ScReduce(data_bytes: bytes) -> bytes:
        """ Convert the specified bytes to integer and return its lowest 32-bytes modulo ed25519-order.
        This ensures that the result is a valid ed25519 scalar to be used as Monero private key.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Lowest 32-bytes modulo ed25519-order
        """
        data_int = ConvUtils.BytesToInteger(data_bytes, endianness="little")
        return ConvUtils.IntegerToBytes(data_int % Ed25519Monero.Order(), bytes_num=32, endianness="little")


class Monero:
    """ Monero class. It allows to compute Monero keys and addresses/subaddresses. """

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> Monero:
        """ Create from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            Monero object: Monero object
        """
        priv_skey_bytes = (seed_bytes
                           if len(seed_bytes) == Ed25519MoneroPrivateKey.Length()
                           else CryptoUtils.Kekkak256(seed_bytes))
        return cls.FromPrivateSpendKey(MoneroUtils.ScReduce(priv_skey_bytes))

    @classmethod
    def FromBip44PrivateKey(cls,
                            priv_key: Union[bytes, IPrivateKey]) -> Monero:
        """ Create from Bip44 private key bytes.

        Args:
            priv_key (bytes or IPrivateKey): Private key

        Returns:
            Monero object: Monero object
        """
        if not isinstance(priv_key, bytes):
            priv_key = priv_key.Raw().ToBytes()
        return cls.FromPrivateSpendKey(MoneroUtils.ScReduce(CryptoUtils.Kekkak256(priv_key)))

    @classmethod
    def FromPrivateSpendKey(cls,
                            priv_skey: Union[bytes, IPrivateKey]) -> Monero:
        """ Create from private spend key.

        Args:
            priv_skey (bytes or IPrivateKey): Private spend key

        Returns:
            Monero object: Monero object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(priv_key=priv_skey)

    @classmethod
    def FromWatchOnly(cls,
                      priv_vkey: Union[bytes, IPrivateKey],
                      pub_skey: Union[bytes, IPublicKey]) -> Monero:
        """ Create from private view key and public spend key (i.e. watch-only wallet).

        Args:
            priv_vkey (bytes or IPrivateKey): Private view key
            pub_skey (bytes or IPublicKey) : Public spend key

        Returns:
            Monero object: Monero object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """
        return cls(priv_key=priv_vkey,
                   pub_key=pub_skey)

    def __init__(self,
                 priv_key: Union[bytes, IPrivateKey],
                 pub_key: Optional[Union[bytes, IPublicKey]] = None) -> None:
        """ Construct class.

        Args:
            priv_key (bytes or IPrivateKey): Private key (view key if watch-only wallet, otherwise spend key)
            pub_key (bytes or IPublicKey)  : Public key (spend key, only needed for watch-only wallets, otherwise None)

        Returns:
            Monero object: Monero object

        Raises:
            MoneroKeyError: If the key constructed from the bytes is not valid
        """

        # Private key object
        if pub_key is None:
            self.m_priv_skey = MoneroPrivateKey.FromBytesOrKeyObject(priv_key)
            self.m_priv_vkey = self.__ViewFromSpendKey(self.m_priv_skey)
            self.m_pub_skey = self.m_priv_skey.PublicKey()
            self.m_pub_vkey = self.m_priv_vkey.PublicKey()
        # Watch-only object
        else:
            self.m_priv_skey = None
            self.m_priv_vkey = MoneroPrivateKey.FromBytesOrKeyObject(priv_key)
            self.m_pub_skey = MoneroPublicKey.FromBytesOrKeyObject(pub_key)
            self.m_pub_vkey = self.m_priv_vkey.PublicKey()

    def IsWatchOnly(self) -> bool:
        """ Return if it's a watch-only object.

        Returns:
            bool: True if watch-only, false otherwise
        """
        return self.m_priv_skey is None

    def PrivateSpendKey(self) -> MoneroPrivateKey:
        """ Return the private spend key.

        Returns:
            MoneroPrivateKey object: MoneroPrivateKey object

        Raises:
            MoneroKeyError: If the class is watch-only
        """
        if self.IsWatchOnly():
            raise MoneroKeyError("Watch-only class has not a private spend key")
        return self.m_priv_skey

    def PrivateViewKey(self) -> MoneroPrivateKey:
        """ Return the private view key.

        Returns:
            MoneroPrivateKey object: MoneroPrivateKey object
        """
        return self.m_priv_vkey

    def PublicSpendKey(self) -> MoneroPublicKey:
        """ Return the public spend key.

        Returns:
            MoneroPublicKey object: MoneroPublicKey object
        """
        return self.m_pub_skey

    def PublicViewKey(self) -> MoneroPublicKey:
        """ Return the public view key.

        Returns:
            MoneroPublicKey object: MoneroPublicKey object
        """
        return self.m_pub_vkey

    @lru_cache()
    def PrimaryAddress(self) -> str:
        """ Return the primary address.

        Returns:
            str: Primary address string
        """
        return XmrAddr.EncodeKey(self.m_pub_skey.KeyObject(),
                                 self.m_pub_vkey.KeyObject(),
                                 MoneroConst.ADDR_MAIN_NET_VER)

    @lru_cache()
    def SubAddress(self,
                   minor_idx: int,
                   major_idx: int = 0) -> str:
        """ Return the specified subaddress.

        Args:
            minor_idx (int)          : Minor index
            major_idx (int, optional): Major index (i.e. account index)

        Returns:
            str: Subaddress string

        Raises:
            ValueError: If one of the indexes is not valid
        """
        if minor_idx < 0 or minor_idx > MoneroConst.SUBADDR_MAX_IDX:
            raise ValueError(f"Invalid minor index ({minor_idx})")
        if major_idx < 0 or major_idx > MoneroConst.SUBADDR_MAX_IDX:
            raise ValueError(f"Invalid major index ({major_idx})")

        return self.__ComputeSubAddress(minor_idx, major_idx)

    def __ComputeSubAddress(self,
                            minor_idx: int,
                            major_idx: int) -> str:
        """ Compute subaddress.

        Args:
            minor_idx (int): Minor index
            major_idx (int): Major index (i.e. account index)

        Returns:
            str: Subaddress string

        Raises:
            ValueError: If one of the indexes is not valid
        """

        # Subaddress 0,0 is the primary address
        if minor_idx == 0 and major_idx == 0:
            return self.PrimaryAddress()

        # Convert indexes to bytes
        major_idx_bytes = ConvUtils.IntegerToBytes(major_idx, bytes_num=MoneroConst.SUBADDR_IDX_BYTE_LEN, endianness="little")
        minor_idx_bytes = ConvUtils.IntegerToBytes(minor_idx, bytes_num=MoneroConst.SUBADDR_IDX_BYTE_LEN, endianness="little")

        # m = Kekkak256("SubAddr" + master_priv_vkey + major_idx + minor_idx)
        m = CryptoUtils.Kekkak256(MoneroConst.SUBADDR_PREFIX + self.m_priv_vkey.Raw().ToBytes() + major_idx_bytes + minor_idx_bytes)
        m_int = ConvUtils.BytesToInteger(m, endianness="little")

        # Compute subaddress public spend key
        # D = master_pub_skey + m * B
        subaddr_pub_skey = self.m_pub_skey.KeyObject().Point() + (Ed25519Monero.Generator() * m_int)

        # Compute subaddress public view key
        # C = master_priv_vkey * D
        subaddr_pub_vkey = subaddr_pub_skey * self.m_priv_vkey.Raw().ToInt("little")

        # Encode subaddress
        return XmrAddr.EncodeKey(subaddr_pub_skey.Raw().ToBytes(),
                                 subaddr_pub_vkey.Raw().ToBytes(),
                                 MoneroConst.SUBADDR_MAIN_NET_VER)

    @staticmethod
    def __ViewFromSpendKey(priv_skey: MoneroPrivateKey) -> MoneroPrivateKey:
        """ Get the private view key from the private spend key.

        Args:
            priv_skey (MoneroPrivateKey object): Private spend key

        Returns:
            MoneroPrivateKey object: Private view key
        """
        priv_vkey_bytes = MoneroUtils.ScReduce(CryptoUtils.Kekkak256(priv_skey.Raw().ToBytes()))
        return MoneroPrivateKey.FromBytes(priv_vkey_bytes)
