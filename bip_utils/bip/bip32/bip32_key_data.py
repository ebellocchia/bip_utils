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

"""Module with helper classes for BIP32 key data."""

# Imports
from __future__ import annotations
from typing import Union
from bip_utils.bip.bip32.bip32_utils import Bip32Utils
from bip_utils.utils.misc import DataBytes, IntegerUtils


class Bip32KeyDataConst:
    """Class container for BIP32 key data constants."""

    # Depth length in bytes
    DEPTH_BYTE_LEN: int = 1
    # Key index length in bytes
    KEY_INDEX_BYTE_LEN: int = 4
    # Key index maximum value
    KEY_INDEX_MAX_VAL: int = 2**32 - 1
    # Chaincode length in bytes
    CHAINCODE_BYTE_LEN: int = 32
    # Fingerprint length in bytes
    FINGERPRINT_BYTE_LEN: int = 4
    # Fingerprint of master key
    FINGERPRINT_MASTER_KEY: bytes = b"\x00\x00\x00\x00"
    # Key net version length in bytes
    KEY_NET_VERSION_LEN: int = 4


class Bip32ChainCode(DataBytes):
    """
    BIP32 chaincode class.
    It represents a BIP32 chaincode.
    """

    def __init__(self,
                 chaincode: bytes = b"\x00" * Bip32KeyDataConst.CHAINCODE_BYTE_LEN) -> None:
        """
        Construct class.

        Args:
            chaincode (bytes, optional): Fingerprint bytes (default: zero)
        """
        if len(chaincode) != Bip32KeyDataConst.CHAINCODE_BYTE_LEN:
            raise ValueError(f"Invalid chaincode length ({len(chaincode)})")
        super().__init__(chaincode)


class Bip32FingerPrint(DataBytes):
    """
    BIP32 fingerprint class.
    It represents a BIP32 fingerprint.
    """

    def __init__(self,
                 fprint: bytes = Bip32KeyDataConst.FINGERPRINT_MASTER_KEY) -> None:
        """
        Construct class.

        Args:
            fprint (bytes, optional): Fingerprint bytes (default: master key)
        """
        if len(fprint) < Bip32KeyDataConst.FINGERPRINT_BYTE_LEN:
            raise ValueError(f"Invalid fingerprint length ({len(fprint)})")
        super().__init__(fprint[:Bip32KeyDataConst.FINGERPRINT_BYTE_LEN])

    def IsMasterKey(self) -> bool:
        """
        Get if the fingerprint corresponds to a master key.

        Returns:
            bool: True if it corresponds to a master key, false otherwise
        """
        return self.ToBytes() == Bip32KeyDataConst.FINGERPRINT_MASTER_KEY


class Bip32Depth:
    """
    BIP32 depth class.
    It represents a BIP32 depth.
    """

    m_depth: int

    def __init__(self,
                 depth: int) -> None:
        """
        Construct class.

        Args:
            depth (int): Depth
        """
        if depth < 0:
            raise ValueError(f"Invalid depth ({depth})")
        self.m_depth = depth

    def Increase(self) -> Bip32Depth:
        """
        Get a new object with increased depth.

        Returns:
            Bip32Depth object: Bip32Depth object
        """
        return Bip32Depth(self.m_depth + 1)

    def ToBytes(self) -> bytes:
        """
        Get the depth as bytes.

        Returns:
            bytes: Depth bytes
        """
        return IntegerUtils.ToBytes(self.m_depth, bytes_num=Bip32KeyDataConst.DEPTH_BYTE_LEN)

    def ToInt(self) -> int:
        """
        Get the depth as integer.

        Returns:
            int: Depth index
        """
        return int(self.m_depth)

    def __int__(self) -> int:
        """
        Get the depth as integer.

        Returns:
            int: Depth index
        """
        return self.ToInt()

    def __bytes__(self) -> bytes:
        """
        Get the depth as bytes.

        Returns:
            bytes: Depth bytes
        """
        return self.ToBytes()

    def __eq__(self,
               other: object) -> bool:
        """
        Equality operator.

        Args:
            other (int or Bip32Depth object): Other value to compare

        Returns:
            bool: True if equal false otherwise
        """
        if not isinstance(other, (int, Bip32Depth)):
            raise TypeError(f"Invalid type for checking equality ({type(other)})")

        if isinstance(other, int):
            return self.m_depth == other
        return self.m_depth == other.m_depth

    def __gt__(self,
               other: Union[int, Bip32Depth]) -> bool:
        """
        Greater than operator.

        Args:
            other (int or Bip32Depth object): Other value to compare

        Returns:
            bool: True if greater false otherwise
        """
        if isinstance(other, int):
            return self.m_depth > other
        return self.m_depth > other.m_depth

    def __lt__(self,
               other: Union[int, Bip32Depth]) -> bool:
        """
        Lower than operator.

        Args:
            other (int or Bip32Depth object): Other value to compare

        Returns:
            bool: True if lower false otherwise
        """
        if isinstance(other, int):
            return self.m_depth < other
        return self.m_depth < other.m_depth


class Bip32KeyIndex:
    """
    BIP32 key index class.
    It represents a BIP32 key index.
    """

    m_idx: int

    def __init__(self,
                 idx: int) -> None:
        """
        Construct class.

        Args:
            idx (int): Key index
        """
        if idx < 0 or idx > Bip32KeyDataConst.KEY_INDEX_MAX_VAL:
            raise ValueError(f"Invalid key index ({idx})")
        self.m_idx = idx

    def IsHardened(self) -> bool:
        """
        Get if the key index is hardened.

        Returns:
            bool: True if hardened, false otherwise
        """
        return Bip32Utils.IsHardenedIndex(self.m_idx)

    def ToBytes(self,
                endianness: str = "big") -> bytes:
        """
        Get the key index as bytes.

        Args:
            endianness (str): Endianness

        Returns:
            bytes: Key bytes
        """
        return IntegerUtils.ToBytes(self.m_idx,
                                    bytes_num=Bip32KeyDataConst.KEY_INDEX_BYTE_LEN,
                                    endianness=endianness)

    def ToInt(self) -> int:
        """
        Get the key index as integer.

        Returns:
            int: Key index
        """
        return int(self.m_idx)

    def __int__(self) -> int:
        """
        Get the key index as integer.

        Returns:
            int: Key index
        """
        return self.ToInt()

    def __bytes__(self) -> bytes:
        """
        Get the key index as bytes.

        Returns:
            bytes: Key bytes
        """
        return self.ToBytes()

    def __eq__(self,
               other: object) -> bool:
        """
        Equality operator.

        Args:
            other (int or Bip32KeyIndex object): Other value to compare

        Returns:
            bool: True if equal false otherwise
        """
        if not isinstance(other, (int, Bip32KeyIndex)):
            raise TypeError(f"Invalid type for checking equality ({type(other)})")

        if isinstance(other, int):
            return self.m_idx == other
        return self.m_idx == other.m_idx


class Bip32KeyNetVersions:
    """
    BIP32 key net versions class.
    It represents a BIP32 key net versions.
    """

    m_pub_net_ver: bytes
    m_priv_net_ver: bytes

    def __init__(self,
                 pub_net_ver: bytes,
                 priv_net_ver: bytes) -> None:
        """
        Construct class.

        Args:
            pub_net_ver (bytes) : Public net version
            priv_net_ver (bytes): Private net version
        """
        if (len(pub_net_ver) != self.Length()
                or len(priv_net_ver) != self.Length()):
            raise ValueError("Invalid key net version length")

        self.m_pub_net_ver = pub_net_ver
        self.m_priv_net_ver = priv_net_ver

    @staticmethod
    def Length() -> int:
        """
        Get the key net version length.

        Returns:
            int: Key net version length
        """
        return Bip32KeyDataConst.KEY_NET_VERSION_LEN

    def Public(self) -> bytes:
        """
        Get public net version.

        Returns:
            bytes: Public net version
        """
        return self.m_pub_net_ver

    def Private(self) -> bytes:
        """
        Get private net version.

        Returns:
            bytes: Private net version
        """
        return self.m_priv_net_ver


class Bip32KeyData:
    """
    BIP32 key data class.
    It contains all additional data related to a BIP32 key (e.g. depth, chain code, etc...).
    """

    m_key_net_ver: Bip32KeyNetVersions
    m_depth: Bip32Depth
    m_index: Bip32KeyIndex
    m_chain_code: Bip32ChainCode
    m_parent_fprint: Bip32FingerPrint

    def __init__(self,
                 key_net_ver: Bip32KeyNetVersions,
                 depth: Bip32Depth,
                 index: Bip32KeyIndex,
                 chain_code: Bip32ChainCode,
                 parent_fprint: Bip32FingerPrint) -> None:
        """
        Construct class.

        Args:
            key_net_ver (Bip32KeyNetVersions object): Bip32KeyNetVersions object
            depth (Bip32Depth object)               : Key depth
            index (Bip32KeyIndex object)            : Key index
            chain_code (Bip32ChainCode object)      : Key chain code
            parent_fprint (Bip32FingerPrint object) : Key parent fingerprint
        """
        self.m_key_net_ver = key_net_ver
        self.m_depth = depth
        self.m_index = index
        self.m_chain_code = chain_code
        self.m_parent_fprint = parent_fprint

    def KeyNetVersions(self) -> Bip32KeyNetVersions:
        """
        Get key net versions.

        Returns:
            Bip32KeyNetVersions object: Bip32KeyNetVersions object
        """
        return self.m_key_net_ver

    def Depth(self) -> Bip32Depth:
        """
        Get current depth.

        Returns:
            Bip32Depth object: Current depth
        """
        return self.m_depth

    def Index(self) -> Bip32KeyIndex:
        """
        Get current index.

        Returns:
            Bip32KeyIndex object: Current index
        """
        return self.m_index

    def ChainCode(self) -> Bip32ChainCode:
        """
        Get current chain code.

        Returns:
            Bip32ChainCode object: Chain code
        """
        return self.m_chain_code

    def ParentFingerPrint(self) -> Bip32FingerPrint:
        """
        Get parent fingerprint.

        Returns:
            Bip32FingerPrint object: Parent fingerprint
        """
        return self.m_parent_fprint
