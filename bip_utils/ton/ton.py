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

"""Module containing utility classes for Ton keys derivation."""

# Imports
from __future__ import annotations

from typing import Union

from bip_utils.ecc.common.ikeys import IPrivateKey, IPublicKey
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PrivateKey, Ed25519PublicKey
from bip_utils.ton.address.ton_address_encoder import TonAddressEncoder


class Ton:
    """
    TON class.
    It allows to generate keys and addresses for TON wallets such as Tonkeeper.
    It also allows to generate addresses based on bip44 such as Trustwallet or Ledger.
    """

    m_priv_key: IPrivateKey
    m_pub_key: IPublicKey

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
            ValueError: If key bytes are not valid
        """
        return cls(Ed25519PrivateKey.FromBytes(seed_bytes[:32]))

    def __init__(self,
                 priv_key: Union[bytes, IPrivateKey]) -> None:
        """
        Construct class.

        Args:
            priv_key (Union[bytes, IPrivateKey]): Private key bytes or object

        Raises:
            ValueError: If key bytes are not valid
            TypeError: If private key is not an Ed25519PrivateKey objec
        """
        if isinstance(priv_key, bytes):
            priv_key = Ed25519PrivateKey.FromBytes(priv_key)
        if not isinstance(priv_key, Ed25519PrivateKey):
            raise TypeError("Private key is not an Ed25519PrivateKey object or bytes")

        self.m_priv_key = priv_key
        self.m_pub_key = priv_key.PublicKey()

    def PublicKey(self) -> IPublicKey:
        """
        Return public key object.

        Returns:
            IPublicKey object: IPublicKey object
        """
        return self.m_pub_key

    def PrivateKey(self) -> IPrivateKey:
        """
        Return private key object.

        Returns:
            IPrivateKey object: IPrivateKey object
        """
        return self.m_priv_key

    def GetAddress(self,
                   version: str = "v5r1",
                   is_bounceable: bool = False) -> str:
        """
        Get address from public key.

        Args:
            version (str, optional): Address version (default: v5r1)
            is_bounceable (bool, optional): Whether the address is bounceable (default: False)

        Returns:
            str: Generated address
        """
        return TonAddressEncoder(self.m_pub_key.RawUncompressed().ToBytes()[1:],
                                 version,
                                 is_bounceable).encode()
