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
from bip_utils.bip32.bip32_utils import Bip32Utils
from bip_utils.conf import KeyNetVersions


class Bip32KeyDataConst:
    """ Class container for BIP32 key data constants. """

    # Fingerprint length in bytes
    FINGERPRINT_BYTE_LEN: int = 4
    # Fingerprint of master key
    MASTER_FINGERPRINT: bytes = b"\x00\x00\x00\x00"


class Bip32FingerPrint:
    """ BIP32 key index class. It represents a BIP32 key index. """

    def __init__(self,
                 fprint: bytes = Bip32KeyDataConst.MASTER_FINGERPRINT) -> None:
        """ Construct class.

        Args:
            fprint (bytes, optional): Fingerprint bytes (default: master key)
        """
        self.m_fprint = fprint[:Bip32KeyDataConst.FINGERPRINT_BYTE_LEN]

    def IsMasterKey(self) -> bool:
        """ Get if the fingerprint corresponds to a master key.

        Returns:
            bool: True if it corresponds to a master key, false otherwise
        """
        return self.m_fprint == Bip32KeyDataConst.MASTER_FINGERPRINT

    def ToBytes(self) -> bytes:
        """ Get fingerprint as bytes.

        Returns:
            bytes: Fingerprint
        """
        return self.m_fprint

    def __bytes__(self) -> bytes:
        """ Get fingerprint as bytes.

        Returns:
            bytes: Fingerprint
        """
        return self.ToBytes()


class Bip32KeyIndex:
    """ BIP32 key index class. It represents a BIP32 key index. """

    def __init__(self,
                 elem: int) -> None:
        """ Construct class.

        Args:
            elem (int): Key index
        """
        self.m_elem = elem

    def IsHardened(self) -> bool:
        """ Get if the key index is hardened.

        Returns:
            bool: True if hardened, false otherwise
        """
        return Bip32Utils.IsHardenedIndex(self.m_elem)

    def ToInt(self) -> int:
        """ Get the key index as integer.

        Returns:
            int: Key index
        """
        return int(self.m_elem)

    def __int__(self) -> int:
        """ Get the key index as integer.

        Returns:
            int: Key index
        """
        return self.ToInt()


class Bip32KeyData:
    """ BIP32 key data class.
    It contains all additional data related to a BIP32 key (e.g. depth, chain code, etc...).
    """

    def __init__(self,
                 key_net_ver: KeyNetVersions,
                 depth: int,
                 index: Bip32KeyIndex,
                 chain_code: bytes,
                 parent_fprint: Bip32FingerPrint) -> None:
        """ Construct class.

        Args:
            key_net_ver (KeyNetVersions object)    : KeyNetVersions object
            depth (int)                            : Key depth
            index (Bip32KeyIndex object)           : Key index
            chain_code (bytes)                     : Key chain code
            parent_fprint (Bip32FingerPrint object): Key parent fingerprint
        """
        self.m_key_net_ver = key_net_ver
        self.m_depth = depth
        self.m_index = index
        self.m_chain_code = chain_code
        self.m_parent_fprint = parent_fprint

    def KeyNetVersions(self) -> KeyNetVersions:
        """ Get key net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """
        return self.m_key_net_ver

    def Depth(self) -> int:
        """ Get current depth.

        Returns:
            int: Current depth
        """
        return self.m_depth

    def Index(self) -> Bip32KeyIndex:
        """ Get current index.

        Returns:
            Bip32KeyIndex object: Current index
        """
        return self.m_index

    def ChainCode(self) -> bytes:
        """ Get current chain code.

        Returns:
            bytes: Current chain code
        """
        return self.m_chain_code

    def ParentFingerPrint(self) -> Bip32FingerPrint:
        """ Get parent fingerprint.

        Returns:
            Bip32FingerPrint object: Parent fingerprint
        """
        return self.m_parent_fprint
