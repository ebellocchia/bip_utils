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
Module for Kaspa address encoding/decoding.
Kaspa addresses use the same bech32 format of Bitcoin Cash addresses, with the address type as version byte.

References:
    https://github.com/kaspanet/rusty-kaspa/blob/master/crypto/addresses/src/lib.rs
    https://github.com/kaspanet/rusty-kaspa/blob/master/crypto/addresses/src/bech32.rs
"""

# Imports
from enum import IntEnum, unique
from typing import Any, Union

from typing_extensions import override

from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.bech32 import BchBech32Decoder, BchBech32Encoder, Bech32ChecksumError
from bip_utils.ecc import IPublicKey, Secp256k1PublicKey
from bip_utils.utils.misc import BytesUtils, IntegerUtils


@unique
class KasAddrTypes(IntEnum):
    """Enumerative for Kaspa address types (the value is the address version byte)."""

    PUB_KEY = 0         # Schnorr public key (32-byte X coordinate)
    PUB_KEY_ECDSA = 1   # ECDSA public key (33-byte compressed public key)


class KasAddrConst:
    """Class container for Kaspa address constants."""

    # Prefix for converting a X coordinate to a compressed public key (only used for validation)
    X_COORD_TO_PUB_KEY_PREFIX: bytes = b"\x02"


class KasAddrDecoder(IAddrDecoder):
    """
    Kaspa address decoder class.
    It allows the Kaspa address decoding.
    """

    @override
    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Kaspa address to bytes.

        Args:
            addr (str): Address string

        Other Parameters:
            hrp (str)                         : Expected HRP
            addr_type (KasAddrTypes, optional): Expected address type (default: public key)

        Returns:
            bytes: X coordinate of the public key (public key type) or compressed public key (ECDSA public key type)

        Raises:
            ValueError: If the address encoding is not valid
            TypeError: If the address type is not a KasAddrTypes enum
        """
        hrp = kwargs["hrp"]
        addr_type = kwargs.get("addr_type", KasAddrTypes.PUB_KEY)
        if not isinstance(addr_type, KasAddrTypes):
            raise TypeError("Address type is not an enumerative of KasAddrTypes")

        try:
            addr_type_bytes, pub_key_bytes = BchBech32Decoder.Decode(hrp, addr)
        except Bech32ChecksumError as ex:
            raise ValueError("Invalid bech32 checksum") from ex

        # Check address type
        addr_type_got = BytesUtils.ToInteger(addr_type_bytes)
        if addr_type != addr_type_got:
            raise ValueError(f"Invalid address type (expected {addr_type.value}, got {addr_type_got})")

        # Validate length and public key
        if addr_type == KasAddrTypes.PUB_KEY:
            AddrDecUtils.ValidateLength(pub_key_bytes, Secp256k1PublicKey.CompressedLength() - 1)
            AddrDecUtils.ValidatePubKey(KasAddrConst.X_COORD_TO_PUB_KEY_PREFIX + pub_key_bytes, Secp256k1PublicKey)
        else:
            AddrDecUtils.ValidateLength(pub_key_bytes, Secp256k1PublicKey.CompressedLength())
            AddrDecUtils.ValidatePubKey(pub_key_bytes, Secp256k1PublicKey)

        return pub_key_bytes


class KasAddrEncoder(IAddrEncoder):
    """
    Kaspa address encoder class.
    It allows the Kaspa address encoding.
    """

    @override
    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Kaspa address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            hrp (str)                         : HRP
            addr_type (KasAddrTypes, optional): Address type (default: public key)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1 or the address type is not a KasAddrTypes enum
        """
        hrp = kwargs["hrp"]
        addr_type = kwargs.get("addr_type", KasAddrTypes.PUB_KEY)
        if not isinstance(addr_type, KasAddrTypes):
            raise TypeError("Address type is not an enumerative of KasAddrTypes")

        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)
        pub_key_bytes = pub_key_obj.RawCompressed().ToBytes()
        # Schnorr public keys only use the X coordinate, i.e. the compressed public key without the prefix byte
        if addr_type == KasAddrTypes.PUB_KEY:
            pub_key_bytes = pub_key_bytes[1:]

        return BchBech32Encoder.Encode(hrp,
                                       IntegerUtils.ToBytes(addr_type),
                                       pub_key_bytes)


# Deprecated: only for compatibility, Encoder class shall be used instead
KasAddr = KasAddrEncoder
