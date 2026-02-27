# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module containing utility classes for Ton keys derivation (ton-crypto style)."""

# Imports
from __future__ import annotations

from typing import Union

from bip_utils.ecc.common.ikeys import IPrivateKey
from bip_utils.ton.addr import (
    TonAddrVersions,
    TonV3R1AddrEncoder,
    TonV3R2AddrEncoder,
    TonV4AddrEncoder,
    TonV5R1AddrEncoder,
)
from bip_utils.ton.ton_keys import TonPrivateKey, TonPublicKey


class Ton:
    """
    TON class.
    It allows to generate keys and addresses for TON wallets like ton-crypto.
    """

    m_priv_key: TonPrivateKey
    m_pub_key: TonPublicKey

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes) -> Ton:
        """
        Construct class from seed bytes.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            Ton object: Ton object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        return cls(seed_bytes[:32])

    def __init__(self,
                 priv_key: Union[bytes, IPrivateKey]) -> None:
        """
        Construct class.

        Args:
            priv_key (Union[bytes, IPrivateKey]): Private key bytes or object

        Raises:
            TonKeyError: If the key constructed from the bytes is not valid
        """
        self.m_priv_key = TonPrivateKey.FromBytesOrKeyObject(priv_key)
        self.m_pub_key = self.m_priv_key.PublicKey()

    def PublicKey(self) -> TonPublicKey:
        """
        Return public key object.

        Returns:
            TonPublicKey object: TonPublicKey object
        """
        return self.m_pub_key

    def PrivateKey(self) -> TonPrivateKey:
        """
        Return private key object.

        Returns:
            TonPrivateKey object: TonPrivateKey object
        """
        return self.m_priv_key

    def GetAddress(self,
                   version: TonAddrVersions = TonAddrVersions.V5R1,
                   is_bounceable: bool = False) -> str:
        """
        Get address from public key.

        Args:
            version (TonAddrVersions, optional): Address version (default: v5r1)
            is_bounceable (bool, optional)     : Whether the address is bounceable (default: False)

        Returns:
            str: Address string
        """
        if version == TonAddrVersions.V5R1:
            return TonV5R1AddrEncoder(self.m_pub_key).Encode(is_bounceable)
        elif version == TonAddrVersions.V4:
            return TonV4AddrEncoder(self.m_pub_key).Encode(is_bounceable)
        elif version == TonAddrVersions.V3R2:
            return TonV3R2AddrEncoder(self.m_pub_key).Encode(is_bounceable)
        else:
            return TonV3R1AddrEncoder(self.m_pub_key).Encode(is_bounceable)
