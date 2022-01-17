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

"""Module with BIP38 utility functions."""

# Imports
from typing import Union
from bip_utils.base58 import Base58Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey, Secp256k1PublicKey
from bip_utils.utils.misc import CryptoUtils
from bip_utils.wif import WifPubKeyModes


# Alias for WifPubKeyModes
Bip38PubKeyModes = WifPubKeyModes


class Bip38AddrConst:
    """Class container for BIP38 address constants."""

    # Address hash length
    ADDR_HASH_LEN: int = 4


class Bip38Addr:
    """Class for BIP38 address computation."""

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  pub_key_mode: Bip38PubKeyModes) -> str:
        """
        Encode a public key to compressed or uncompressed address.

        Args:
            pub_key (bytes or IPublicKey)  : Public key bytes or object
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            str: Encoded address

        Raises:
            TypeError: If the public key is not a Secp256k1PublicKey
            ValueError: If the public key bytes are not valid
        """

        # Convert to public key to check if bytes are valid
        if isinstance(pub_key, bytes):
            pub_key = Secp256k1PublicKey.FromBytes(pub_key)
        elif not isinstance(pub_key, Secp256k1PublicKey):
            raise TypeError("A secp256k1 public key is required")

        # Get public key bytes
        pub_key_bytes = (pub_key.RawCompressed().ToBytes()
                         if pub_key_mode == Bip38PubKeyModes.COMPRESSED
                         else pub_key.RawUncompressed().ToBytes())

        # Encode key to address
        net_ver = CoinsConf.BitcoinMainNet.Params("p2pkh_net_ver")
        return Base58Encoder.CheckEncode(net_ver + CryptoUtils.Hash160(pub_key_bytes))

    @staticmethod
    def AddressHash(pub_key: Union[bytes, IPublicKey],
                    pub_key_mode: Bip38PubKeyModes) -> bytes:
        """
        Compute the address hash as specified in BIP38.

        Args:
            pub_key (bytes or IPublicKey)  : Public key bytes or object
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            bytes: Address hash

        Raises:
            TypeError: If the public key is not a Secp256k1PublicKey
            ValueError: If the public key bytes are not valid
        """

        # Compute the Bitcoin address
        address = Bip38Addr.EncodeKey(pub_key, pub_key_mode)
        # Take the first four bytes of SHA256(SHA256())
        return CryptoUtils.DoubleSha256(address)[:Bip38AddrConst.ADDR_HASH_LEN]
