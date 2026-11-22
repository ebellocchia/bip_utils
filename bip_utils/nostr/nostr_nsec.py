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

"""
Module for Nostr private key encoding/decoding (nsec format).
Reference: https://github.com/nostr-protocol/nips/blob/master/19.md
"""

# Imports
from typing import Union

from bip_utils.bech32 import Bech32Decoder, Bech32Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPrivateKey, Secp256k1PrivateKey


class NostrNsecEncoder:
    """
    Nostr nsec encoder class.
    It provides methods for encoding private keys to nsec format.
    """

    @staticmethod
    def Encode(priv_key: Union[bytes, IPrivateKey]) -> str:
        """
        Encode a private key to nsec format.

        Args:
            priv_key (bytes or IPrivateKey): Private key bytes or object

        Returns:
            str: nsec string

        Raises:
            TypeError: If the private key is not a Secp256k1PrivateKey
            ValueError: If the private key is not valid
        """

        # Convert to private key to check if bytes are valid
        if isinstance(priv_key, bytes):
            priv_key = Secp256k1PrivateKey.FromBytes(priv_key)
        elif not isinstance(priv_key, Secp256k1PrivateKey):
            raise TypeError("A secp256k1 private key is required")

        return Bech32Encoder.Encode(CoinsConf.Nostr.ParamByKey("priv_key_hrp"),
                                    priv_key.Raw().ToBytes())


class NostrNsecDecoder:
    """
    Nostr nsec decoder class.
    It provides methods for decoding private keys from nsec format.
    """

    @staticmethod
    def Decode(nsec_str: str) -> bytes:
        """
        Decode a private key from nsec format.

        Args:
            nsec_str (str): nsec string

        Returns:
            bytes: Private key bytes

        Raises:
            Bech32ChecksumError: If the bech32 checksum is not valid
            ValueError: If the nsec string or the resulting private key is not valid
        """
        priv_key_bytes = Bech32Decoder.Decode(CoinsConf.Nostr.ParamByKey("priv_key_hrp"), nsec_str)
        # Convert to private key to check if bytes are valid
        return Secp256k1PrivateKey.FromBytes(priv_key_bytes).Raw().ToBytes()
