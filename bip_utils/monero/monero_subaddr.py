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

"""Module for Monero subaddress computation."""

# Imports
from typing import Optional, Tuple

from bip_utils.addr import XmrAddrEncoder
from bip_utils.ecc import Ed25519Monero, Ed25519Utils
from bip_utils.monero.monero_keys import MoneroPrivateKey, MoneroPublicKey
from bip_utils.utils.crypto import Kekkak256
from bip_utils.utils.misc import IntegerUtils


class MoneroSubaddressConst:
    """Class container for Monero subaddress constants."""

    # Subaddress prefix
    SUBADDR_PREFIX: bytes = b"SubAddr\x00"
    # Subaddress maximum index
    SUBADDR_MAX_IDX: int = 2**32 - 1
    # Subaddress index length in byte
    SUBADDR_IDX_BYTE_LEN: int = 4


class MoneroSubaddress:
    """Monero subaddress class. It allows to compute Monero subaddresses."""

    m_priv_vkey: MoneroPrivateKey
    m_pub_skey: MoneroPublicKey
    m_pub_vkey: MoneroPublicKey

    def __init__(self,
                 priv_vkey: MoneroPrivateKey,
                 pub_skey: MoneroPublicKey,
                 pub_vkey: Optional[MoneroPublicKey] = None) -> None:
        """
        Construct class.

        Args:
            priv_vkey (MoneroPrivateKey)        : Private view key
            pub_skey (MoneroPublicKey)          : Public spend key
            pub_vkey (MoneroPublicKey, optional): Public view key (if None, it'll be computed from the private one)
        """
        self.m_priv_vkey = priv_vkey
        self.m_pub_skey = pub_skey
        self.m_pub_vkey = pub_vkey if pub_vkey is not None else priv_vkey.PublicKey()

    def ComputeKeys(self,
                    minor_idx: int,
                    major_idx: int) -> Tuple[MoneroPublicKey, MoneroPublicKey]:
        """
        Compute the public keys of the specified subaddress.

        Args:
            minor_idx (int): Minor index (i.e. subaddress index)
            major_idx (int): Major index (i.e. account index)

        Returns:
            tuple[MoneroPublicKey, MoneroPublicKey]: Computed public spend key (index 0) and public view key (index 1)

        Raises:
            ValueError: If one of the indexes is not valid
        """
        if minor_idx < 0 or minor_idx > MoneroSubaddressConst.SUBADDR_MAX_IDX:
            raise ValueError(f"Invalid minor index ({minor_idx})")
        if major_idx < 0 or major_idx > MoneroSubaddressConst.SUBADDR_MAX_IDX:
            raise ValueError(f"Invalid major index ({major_idx})")

        # Subaddress 0,0 is the primary address
        if minor_idx == 0 and major_idx == 0:
            return self.m_pub_skey, self.m_pub_vkey

        # Convert indexes to bytes
        major_idx_bytes = IntegerUtils.ToBytes(major_idx,
                                               bytes_num=MoneroSubaddressConst.SUBADDR_IDX_BYTE_LEN,
                                               endianness="little")
        minor_idx_bytes = IntegerUtils.ToBytes(minor_idx,
                                               bytes_num=MoneroSubaddressConst.SUBADDR_IDX_BYTE_LEN,
                                               endianness="little")

        # m = Kekkak256("SubAddr" + master_priv_vkey + major_idx + minor_idx)
        m = Kekkak256.QuickDigest(MoneroSubaddressConst.SUBADDR_PREFIX
                                  + self.m_priv_vkey.Raw().ToBytes()
                                  + major_idx_bytes
                                  + minor_idx_bytes)
        m_int = Ed25519Utils.IntDecode(Ed25519Utils.ScalarReduce(m))

        # Compute subaddress public spend key
        # D = master_pub_skey + m * B
        subaddr_pub_skey_point = self.m_pub_skey.KeyObject().Point() + (Ed25519Monero.Generator() * m_int)

        # Compute subaddress public view key
        # C = master_priv_vkey * D
        subaddr_pub_vkey_point = subaddr_pub_skey_point * self.m_priv_vkey.Raw().ToInt("little")

        return (MoneroPublicKey.FromPoint(subaddr_pub_skey_point),
                MoneroPublicKey.FromPoint(subaddr_pub_vkey_point))

    def ComputeAndEncodeKeys(self,
                             minor_idx: int,
                             major_idx: int,
                             net_ver: bytes) -> str:
        """
        Compute the public keys of the specified subaddress and encode them.

        Args:
            minor_idx (int): Minor index (i.e. subaddress index)
            major_idx (int): Major index (i.e. account index)
            net_ver (bytes): Net version

        Returns:
            str: Encoded subaddress string

        Raises:
            ValueError: If one of the indexes is not valid
        """
        pub_skey, pub_vkey = self.ComputeKeys(minor_idx, major_idx)

        # Encode subaddress
        return XmrAddrEncoder.EncodeKey(pub_skey.KeyObject(),
                                        pub_vkey=pub_vkey.KeyObject(),
                                        net_ver=net_ver)
