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

"""
Module for Cardano Byron address encoding/decoding.
References:
    https://cips.cardano.org/cips/cip19
    https://raw.githubusercontent.com/cardano-foundation/CIPs/master/CIP-0019/CIP-0019-byron-addresses.cddl
"""

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
class AdaByronAddrTypes(IntEnum):
    """Enumerative for Cardano Byron address types."""

    PUBLIC_KEY = 0
    REDEMPTION = 2


class AdaByronAddrConst:
    """Class container for Cardano Byron address constants."""

    # Hash length in bytes
    HASH_BYTE_LEN: int = 28
    # Payload tag
    PAYLOAD_TAG: int = 24


class _AdaByronAddrUtils:
    """Cardano Byron address utility class."""

    @staticmethod
    def KeyDoubleHash(key_bytes: bytes,
                      addr_attrs: Dict,
                      addr_type: AdaByronAddrTypes) -> bytes:
        """
        Compute the key double hash.

        Args:
            key_bytes (bytes)            : Key bytes
            addr_attrs (dict)            : Address attributes
            addr_type (AdaByronAddrTypes): Address type

        Returns:
            bytes: Key hash bytes
        """
        addr_root = cbor2.dumps([
            addr_type,                  # Address type
            [addr_type, key_bytes],     # Address spending data
            addr_attrs,                 # Address attributes
        ])
        return CryptoUtils.Blake2b(CryptoUtils.Sha3_256(addr_root),
                                   AdaByronAddrConst.HASH_BYTE_LEN)


class AdaByronAddrDecoder(IAddrDecoder):
    """
    Cardano Byron address decoder class.
    It allows the Cardano Byron address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano Byron address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public key/chain code hash bytes (first 28-byte) and encrypted HD path (if present)

        Raises:
            ValueError: If the address encoding is not valid
        """

        try:
            # Decode from base58
            addr_payload_with_crc = cbor2.loads(Base58Decoder.Decode(addr))
            if (len(addr_payload_with_crc) != 2
                    or not isinstance(addr_payload_with_crc[0], cbor2.CBORTag)
                    or not isinstance(addr_payload_with_crc[1], int)):
                raise ValueError("Invalid address encoding")
            # Get and check CBOR tag
            cbor_tag = addr_payload_with_crc[0]
            if cbor_tag.tag != AdaByronAddrConst.PAYLOAD_TAG:
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
                raise ValueError("Invalid address payload")
            # Get and check address attributes
            addr_attrs = addr_payload[1]
            if (len(addr_attrs) > 2
                    or (len(addr_attrs) != 0 and 1 not in addr_attrs and 2 not in addr_attrs)):
                raise ValueError("Invalid address attributes")
            # Get encrypted HD path
            hd_path_enc_bytes = cbor2.loads(addr_attrs[1]) if 1 in addr_attrs else b""
            # Check address type
            if addr_payload[2] not in (AdaByronAddrTypes.PUBLIC_KEY, AdaByronAddrTypes.REDEMPTION):
                raise ValueError(f"Invalid address type ({addr_payload[2]})")
            # Check key hash length
            AddrDecUtils.ValidateLength(addr_payload[0],
                                        AdaByronAddrConst.HASH_BYTE_LEN)

            return addr_payload[0] + hd_path_enc_bytes
        except cbor2.CBORDecodeValueError as ex:
            raise ValueError("Invalid CBOR encoding") from ex


class AdaByronAddrEncoder(IAddrEncoder):
    """
    Cardano Byron address encoder class.
    It allows the Cardano Byron address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Cardano Byron address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            chain_code (bytes or Bip32ChainCode object): Chain code bytes or object
                                                         (ignored if address type is redemption)
            addr_type (AdaByronAddrTypes)                : Address type (default: public key)
            hd_path_enc (bytes)                          : Encrypted HD path bytes (default: empty)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519 or the address type is not a AdaByronAddrTypes enum
        """
        addr_attrs = {}

        # Get address type
        addr_type = kwargs.get("addr_type", AdaByronAddrTypes.PUBLIC_KEY)
        if not isinstance(addr_type, AdaByronAddrTypes):
            raise TypeError("Address type is not an enumerative of AdaByronAddrTypes")
        # Get encrypted HD path
        if "hd_path_enc" in kwargs:
            addr_attrs[1] = cbor2.dumps(kwargs["hd_path_enc"])

        # Get chain code only if address type is public key
        if addr_type == AdaByronAddrTypes.PUBLIC_KEY:
            chain_code = kwargs["chain_code"]
            # Creating a Bip32ChainCode object checks for bytes validity
            chain_code_bytes = (Bip32ChainCode(chain_code).ToBytes()
                                if isinstance(chain_code, bytes)
                                else chain_code.ToBytes())
        else:
            chain_code_bytes = b""

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)

        # Get key hash
        key_hash_bytes = _AdaByronAddrUtils.KeyDoubleHash(pub_key_obj.RawCompressed().ToBytes()[1:] + chain_code_bytes,
                                                          addr_attrs, addr_type)
        # Get address payload
        addr_payload = cbor2.dumps([
            key_hash_bytes,     # Key double hash
            addr_attrs,         # Address attributes
            addr_type,          # Address type
        ])
        # Add CRC32 and encode to base58
        return Base58Encoder.Encode(
            cbor2.dumps([
                cbor2.CBORTag(AdaByronAddrConst.PAYLOAD_TAG, addr_payload),
                CryptoUtils.Crc32(addr_payload),
            ])
        )


# For compatibility with old versions, Encoder class shall be used instead
AdaByronAddr = AdaByronAddrEncoder
