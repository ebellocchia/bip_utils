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

"""Module for Cardano V2 address encoding/decoding."""

# Imports
from enum import IntEnum, unique
from typing import Any, Dict, Union
import cbor2
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip32 import Bip32ChainCode
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils


@unique
class AdaV2AddrTypes(IntEnum):
    """Enumerative for Cardano V2 address types."""

    PUBLIC_KEY = 0
    REDEMPTION = 2


class AdaV2AddrConst:
    """Class container for Cardano V2 address constants."""

    # Hash length in bytes
    HASH_BYTE_LEN: int = 28
    # Payload tag
    PAYLOAD_TAG: int = 24


class _AdaV2AddrUtils:
    """Cardano V2 address utility class."""

    @staticmethod
    def KeyHash(pub_key_bytes: bytes,
                chain_code_bytes: bytes,
                addr_attrs: Dict,
                addr_type: AdaV2AddrTypes) -> bytes:
        """
        Compute the key hash.

        Args:
            pub_key_bytes (bytes)     : Public key bytes
            chain_code_bytes (bytes)  : Chain code bytes
            addr_attrs (dict)         : Address attributes
            addr_type (AdaV2AddrTypes): Address type

        Returns:
            bytes: Key hash bytes
        """
        addr_root = cbor2.dumps([
            addr_type,
            [0, pub_key_bytes + chain_code_bytes],
            addr_attrs
        ])
        # Compute double hash: Blake2b-224(SHA3-256())
        return CryptoUtils.Blake2b(CryptoUtils.Sha3_256(addr_root),
                                   AdaV2AddrConst.HASH_BYTE_LEN)


class AdaV2AddrDecoder(IAddrDecoder):
    """
    Cardano V2 address decoder class.
    It allows the Cardano V2 address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano V2 address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public key and chain code hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """

        # Decode from base58
        addr_payload_with_crc = cbor2.loads(Base58Decoder.Decode(addr))
        if (len(addr_payload_with_crc) != 2
                or not isinstance(addr_payload_with_crc[0], cbor2.CBORTag)
                or not isinstance(addr_payload_with_crc[1], int)):
            raise ValueError("Invalid address encoding")
        # Get and check CBOR tag
        cbor_tag = addr_payload_with_crc[0]
        if cbor_tag.tag != AdaV2AddrConst.PAYLOAD_TAG:
            raise ValueError(f"Invalid CBOR tag ({cbor_tag.tag})")
        # Check CRC
        crc32_got = CryptoUtils.Crc32(cbor_tag.value)
        if crc32_got != addr_payload_with_crc[1]:
            raise ValueError(f"Invalid CRC (expected: {addr_payload_with_crc[1]}, got: {crc32_got})")
        # Get and check tag value
        addr_payload = cbor2.loads(cbor_tag.value)
        if (len(addr_payload) != 3
                or not isinstance(addr_payload[0], bytes)
                or not isinstance(addr_payload[1], dict)
                or not isinstance(addr_payload[2], int)):
            raise ValueError("Invalid CBOR tag value")
        # Check address type
        if addr_payload[2] not in (AdaV2AddrTypes.PUBLIC_KEY, AdaV2AddrTypes.REDEMPTION):
            raise ValueError(f"Invalid address type ({addr_payload[2]})")
        # Check key hash length
        AddrDecUtils.ValidateLength(addr_payload[0],
                                    AdaV2AddrConst.HASH_BYTE_LEN)

        return addr_payload[0]


class AdaV2AddrEncoder(IAddrEncoder):
    """
    Cardano V2 address encoder class.
    It allows the Cardano V2 address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Cardano address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            chain_code (bytes or Bip32ChainCode object): Chain code bytes or object
            addr_attrs (dict)                          : Address attributes (default: empty dict)
            addr_type (AdaV2AddrTypes)                 : Address type (default: public key)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        chain_code = kwargs["chain_code"]
        if isinstance(chain_code, bytes):
            chain_code = Bip32ChainCode(chain_code)
        addr_attrs = kwargs.get("addr_attrs", {})
        addr_type = kwargs.get("addr_type", AdaV2AddrTypes.PUBLIC_KEY)

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)

        # Get key hash
        key_hash_bytes = _AdaV2AddrUtils.KeyHash(
            pub_key_obj.RawCompressed().ToBytes()[1:],
            chain_code.ToBytes(),
            addr_attrs,
            addr_type
        )
        # Get address payload
        addr_payload = cbor2.dumps([
            key_hash_bytes,
            addr_attrs,
            addr_type,
        ])
        # Add CRC32 and encode to base58
        return Base58Encoder.Encode(cbor2.dumps([
            cbor2.CBORTag(AdaV2AddrConst.PAYLOAD_TAG, addr_payload),
            CryptoUtils.Crc32(addr_payload)
        ]))


class AdaV2Addr(AdaV2AddrEncoder):
    """
    Cardano V3 address class.
    Only kept for compatibility, AdaV3AddrEncoder shall be used instead.
    """
