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
Module for Cardano Byron address encoding/decoding. Both legacy and Icarus addresses are supported.

References:
    https://cips.cardano.org/cips/cip19
    https://raw.githubusercontent.com/cardano-foundation/CIPs/master/CIP-0019/CIP-0019-byron-addresses.cddl
"""

# Imports
from enum import IntEnum, unique
from typing import Any, Dict, Optional, Tuple, Union
import cbor2
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip32 import Bip32ChainCode, Bip32Path, Bip32PathParser
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CborIndefiniteLenArrayDecoder, CborIndefiniteLenArrayEncoder, CryptoUtils


@unique
class AdaByronAddrTypes(IntEnum):
    """Enumerative for Cardano Byron address types."""

    PUBLIC_KEY = 0
    REDEMPTION = 2


class AdaByronAddrConst:
    """Class container for Cardano Byron address constants."""

    # ChaCha20-Poly1305 nonce for HD path decryption/encryption
    CHACHA20_POLY1305_NONCE: bytes = b"serokellfore"
    # ChaCha20-Poly1305 associated data for HD path decryption/encryption
    CHACHA20_POLY1305_ASSOC_DATA: bytes = b""
    # ChaCha20-Poly1305 tag length in bytes
    CHACHA20_POLY1305_TAG_BYTE_LEN: int = 16
    # Address root hash length in bytes
    ADDR_ROOT_HASH_BYTE_LEN: int = 28
    # HD path key length in bytes
    HD_PATH_KEY_BYTE_LEN: int = 32
    # Payload tag
    PAYLOAD_TAG: int = 24


class _AdaByronAddrHdPath:
    """Cardano Byron address HD path class."""

    @staticmethod
    def Decrypt(hd_path_enc_bytes: bytes,
                hd_path_key_bytes: bytes) -> Bip32Path:
        """
        Encrypt the HD path.

        Args:
            hd_path_enc_bytes (bytes): Encrypted HD path bytes
            hd_path_key_bytes (bytes): HD path key bytes

        Returns:
            Bip32Path object: Bip32Path object

        Raises:
            ValueError: If the decryption fails or the path cannot be decoded
        """
        plain_text_bytes = CryptoUtils.ChaCha20Poly1305Decrypt(
            key=hd_path_key_bytes,
            nonce=AdaByronAddrConst.CHACHA20_POLY1305_NONCE,
            assoc_data=AdaByronAddrConst.CHACHA20_POLY1305_ASSOC_DATA,
            cipher_text=hd_path_enc_bytes[:-AdaByronAddrConst.CHACHA20_POLY1305_TAG_BYTE_LEN],
            tag=hd_path_enc_bytes[-AdaByronAddrConst.CHACHA20_POLY1305_TAG_BYTE_LEN:]
        )
        return Bip32Path(CborIndefiniteLenArrayDecoder.Decode(plain_text_bytes),
                         True)

    @staticmethod
    def Encrypt(hd_path: Bip32Path,
                hd_path_key_bytes: bytes) -> bytes:
        """
        Encrypt the HD path.

        Args:
            hd_path (Bip32Path object): HD path
            hd_path_key_bytes (bytes) : HD path key bytes

        Returns:
            bytes: Computed key bytes
        """
        cipher_text_bytes, tag_bytes = CryptoUtils.ChaCha20Poly1305Encrypt(
            key=hd_path_key_bytes,
            nonce=AdaByronAddrConst.CHACHA20_POLY1305_NONCE,
            assoc_data=AdaByronAddrConst.CHACHA20_POLY1305_ASSOC_DATA,
            plain_text=CborIndefiniteLenArrayEncoder.Encode(hd_path.ToList())
        )
        return cipher_text_bytes + tag_bytes


class _AdaByronAddrUtils:
    """Cardano Byron address utility class."""

    @staticmethod
    def AddressRootHash(key_bytes: bytes,
                        addr_attrs: Dict[int, bytes],
                        addr_type: AdaByronAddrTypes) -> bytes:
        """
        Compute the address root hash.

        Args:
            key_bytes (bytes)            : Key bytes
            addr_attrs (dict[int, bytes]): Address attributes
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
                                   AdaByronAddrConst.ADDR_ROOT_HASH_BYTE_LEN)

    @staticmethod
    def EncodeKey(pub_key_bytes: bytes,
                  chain_code_bytes: bytes,
                  addr_type: AdaByronAddrTypes,
                  hd_path_enc_bytes: Optional[bytes] = None) -> str:
        """
        Encode a public key to Cardano Byron address.

        Args:
            pub_key_bytes (bytes)              : Public key bytes
            chain_code_bytes (bytes)           : Chain code bytes
            addr_type (AdaByronAddrTypes)      : Address type
            hd_path_enc_bytes (bytes, optional): Encrypted HD path bytes

        Returns:
            str: Address string
        """
        addr_attrs = {}
        if hd_path_enc_bytes is not None:
            addr_attrs[1] = cbor2.dumps(hd_path_enc_bytes)

        # Get key hash
        key_hash_bytes = _AdaByronAddrUtils.AddressRootHash(
            pub_key_bytes[1:] + chain_code_bytes, addr_attrs, addr_type)
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


class AdaByronAddrDecoder(IAddrDecoder):
    """
    Cardano Byron address decoder class.
    It allows the Cardano Byron address decoding.
    """

    @staticmethod
    def DecryptHdPath(hd_path_enc_bytes: bytes,
                      hd_path_key_bytes: bytes) -> Bip32Path:
        """
        Decrypt an HD path using the specified key.

        Args:
            hd_path_enc_bytes (bytes): Encrypted HD path bytes
            hd_path_key_bytes (bytes): HD path key bytes

        Returns:
            Bip32Path object: Bip32Path object

        Raises:
            ValueError: If the decryption fails
        """
        return _AdaByronAddrHdPath.Decrypt(hd_path_enc_bytes, hd_path_key_bytes)

    @staticmethod
    def SplitDecodedBytes(dec_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Split the decoded bytes into address root hash and encrypted HD path.

        Args:
            dec_bytes (bytes): Decoded bytes

        Returns:
            tuple[bytes, bytes]: Address root hash (index 0), encrypted HD path (index 1)
        """
        return (dec_bytes[:AdaByronAddrConst.ADDR_ROOT_HASH_BYTE_LEN],
                dec_bytes[AdaByronAddrConst.ADDR_ROOT_HASH_BYTE_LEN:])

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano Byron address (either legacy or Icarus) to bytes.
        The result can be split with SplitDecodedBytes if needed, to get the address root hash and
        encrypted HD path separately.

        Args:
            addr (str): Address string

        Other Parameters:
            addr_type (AdaByronAddrTypes): Expected address type (default: public key)

        Returns:
            bytes: Address root hash bytes (first 28-byte) and encrypted HD path (following bytes, if present)

        Raises:
            ValueError: If the address encoding is not valid
            TypeError: If the address type is not a AdaByronAddrTypes enum
        """
        addr_type = kwargs.get("addr_type", AdaByronAddrTypes.PUBLIC_KEY)
        if not isinstance(addr_type, AdaByronAddrTypes):
            raise TypeError("Address type is not an enumerative of AdaByronAddrTypes")

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
            if addr_payload[2] != addr_type:
                raise ValueError(f"Invalid address type (expected: {addr_type}, got: {addr_payload[2]})")
            # Check key hash length
            AddrDecUtils.ValidateLength(addr_payload[0],
                                        AdaByronAddrConst.ADDR_ROOT_HASH_BYTE_LEN)

            return addr_payload[0] + hd_path_enc_bytes
        except cbor2.CBORDecodeValueError as ex:
            raise ValueError("Invalid CBOR encoding") from ex


class AdaByronIcarusAddrEncoder(IAddrEncoder):
    """
    Cardano Byron Icarus address encoder class.
    It allows the Cardano Byron Icarus address encoding (i.e. without the encrypted derivation path, format Ae2...).
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

        Returns:
            str: Address string

        Raises:
            Bip32PathError: If the path indexes are not valid
            ValueError: If the public key, the chain code or the HD path key is not valid
            TypeError: If the public key is not ed25519
        """

        # Get chain code (creating a Bip32ChainCode object checks for its validity)
        chain_code = kwargs["chain_code"]
        chain_code_bytes = (Bip32ChainCode(chain_code).ToBytes()
                            if isinstance(chain_code, bytes)
                            else chain_code.ToBytes())

        return _AdaByronAddrUtils.EncodeKey(
            AddrKeyValidator.ValidateAndGetEd25519Key(pub_key).RawCompressed().ToBytes(),
            chain_code_bytes,
            AdaByronAddrTypes.PUBLIC_KEY
        )


class AdaByronLegacyAddrEncoder(IAddrEncoder):
    """
    Cardano Byron legacy address encoder class.
    It allows the Cardano Byron legacy address encoding (i.e. containing the encrypted derivation path, format Ddz...).
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
            hd_path (str or Bip32Path object)          : HD path
            hd_path_key (bytes)                        : HD path key bytes, shall be 32-byte long

        Returns:
            str: Address string

        Raises:
            Bip32PathError: If the path indexes are not valid
            ValueError: If the public key, the chain code or the HD path key is not valid
            TypeError: If the public key is not ed25519
        """

        # Get HD path
        hd_path = kwargs["hd_path"]
        if isinstance(hd_path, str):
            hd_path = Bip32PathParser.Parse(hd_path)

        # Get HD path key
        hd_path_key_bytes = kwargs["hd_path_key"]
        if hd_path_key_bytes is not None and len(hd_path_key_bytes) != AdaByronAddrConst.HD_PATH_KEY_BYTE_LEN:
            raise ValueError("HD path key shall be 32-byte long")

        # Get chain code (creating a Bip32ChainCode object checks for its validity)
        chain_code = kwargs["chain_code"]
        chain_code_bytes = (Bip32ChainCode(chain_code).ToBytes()
                            if isinstance(chain_code, bytes)
                            else chain_code.ToBytes())

        return _AdaByronAddrUtils.EncodeKey(
            AddrKeyValidator.ValidateAndGetEd25519Key(pub_key).RawCompressed().ToBytes(),
            chain_code_bytes,
            AdaByronAddrTypes.PUBLIC_KEY,
            _AdaByronAddrHdPath.Encrypt(hd_path, hd_path_key_bytes) if hd_path_key_bytes is not None else None
        )


# For compatibility with old versions, Encoder class shall be used instead
AdaByronIcarusAddr = AdaByronIcarusAddrEncoder
AdaByronLegacyAddr = AdaByronLegacyAddrEncoder
