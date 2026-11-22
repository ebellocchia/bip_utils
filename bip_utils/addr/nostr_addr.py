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
Module for Nostr address encoding/decoding.
A Nostr address is the public key (X coordinate only) encoded in bech32 with the "npub" HRP (NIP-19).

References:
    https://github.com/nostr-protocol/nips/blob/master/01.md
    https://github.com/nostr-protocol/nips/blob/master/19.md
"""

# Imports
from typing import Any, Union

from typing_extensions import override

from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey, Secp256k1PublicKey


class NostrAddrConst:
    """Class container for Nostr address constants."""

    # Prefix for converting a X coordinate to a compressed public key (only used for validation)
    X_COORD_TO_PUB_KEY_PREFIX: bytes = b"\x02"


class NostrAddrDecoder(IAddrDecoder):
    """
    Nostr address decoder class.
    It allows the Nostr address (npub) decoding.
    """

    @override
    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Nostr address (npub) to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: X coordinate of the public key

        Raises:
            ValueError: If the address encoding is not valid
        """
        try:
            pub_key_bytes = Bech32Decoder.Decode(CoinsConf.Nostr.ParamByKey("addr_hrp"), addr)
        except Bech32ChecksumError as ex:
            raise ValueError("Invalid bech32 checksum") from ex

        # Validate length and public key
        AddrDecUtils.ValidateLength(pub_key_bytes, Secp256k1PublicKey.CompressedLength() - 1)
        AddrDecUtils.ValidatePubKey(NostrAddrConst.X_COORD_TO_PUB_KEY_PREFIX + pub_key_bytes, Secp256k1PublicKey)

        return pub_key_bytes


class NostrAddrEncoder(IAddrEncoder):
    """
    Nostr address encoder class.
    It allows the Nostr address (npub) encoding.
    """

    @override
    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Nostr address (npub).

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs                     : Not used

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)
        # Nostr public keys only use the X coordinate, i.e. the compressed public key without the prefix byte
        return Bech32Encoder.Encode(CoinsConf.Nostr.ParamByKey("addr_hrp"),
                                    pub_key_obj.RawCompressed().ToBytes()[1:])


# Deprecated: only for compatibility, Encoder class shall be used instead
NostrAddr = NostrAddrEncoder
