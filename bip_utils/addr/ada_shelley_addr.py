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

"""Module for Cardano Shelley address encoding/decoding."""

# Imports
from enum import IntEnum, unique
from typing import Any, Dict, Tuple, Union
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils, IntegerUtils


@unique
class AdaShelleyAddrNetworkTags(IntEnum):
    """Enumerative for Cardano Shelley network tags."""

    TESTNET = 0
    MAINNET = 1


@unique
class AdaShelleyAddrHeaderTypes(IntEnum):
    """Enumerative for Cardano Shelley header types."""

    PAYMENT = 0x00
    REWARD = 0x0E


class AdaShelleyAddrConst:
    """Class container for Cardano Shelley address constants."""

    # Hash length in bytes
    HASH_BYTE_LEN: int = 28
    # Network tag to address HRP
    NETWORK_TAG_TO_ADDR_HRP: Dict[AdaShelleyAddrNetworkTags, str] = {
        AdaShelleyAddrNetworkTags.MAINNET: CoinsConf.CardanoMainNet.ParamByKey("addr_hrp"),
        AdaShelleyAddrNetworkTags.TESTNET: CoinsConf.CardanoTestNet.ParamByKey("addr_hrp"),
    }
    # Network tag to reward address HRP
    NETWORK_TAG_TO_REWARD_ADDR_HRP: Dict[AdaShelleyAddrNetworkTags, str] = {
        AdaShelleyAddrNetworkTags.MAINNET: CoinsConf.CardanoMainNet.ParamByKey("reward_addr_hrp"),
        AdaShelleyAddrNetworkTags.TESTNET: CoinsConf.CardanoTestNet.ParamByKey("reward_addr_hrp"),
    }


class _AdaShelleyAddrUtils:
    """Cardano Shelley address utility class."""

    @staticmethod
    def KeyHash(pub_key_bytes: bytes) -> bytes:
        """
        Compute the key hash.

        Args:
            pub_key_bytes (bytes): Public key bytes

        Returns:
            bytes: Key hash bytes
        """
        return CryptoUtils.Blake2b(pub_key_bytes,
                                   AdaShelleyAddrConst.HASH_BYTE_LEN)

    @staticmethod
    def DecodeFirstAddrByte(first_byte: int) -> Tuple[AdaShelleyAddrHeaderTypes, AdaShelleyAddrNetworkTags]:
        """
        Decode first address byte.

        Args:
            first_byte (int): First address byte

        Returns:
            tuple[AdaShelleyAddrHeaderTypes, AdaShelleyAddrNetworkTags]: header type (index 0), network tag (index 1)
        """
        return AdaShelleyAddrHeaderTypes(first_byte >> 4), AdaShelleyAddrNetworkTags(first_byte & 0x0F)

    @staticmethod
    def EncodeFirstAddrByte(hdr_type: AdaShelleyAddrHeaderTypes,
                            net_tag: AdaShelleyAddrNetworkTags) -> bytes:
        """
        Encode first address byte.

        Args:
            hdr_type (AdaShelleyAddrHeaderTypes): Header type
            net_tag (AdaShelleyAddrNetworkTags) : Network tag

        Returns:
            bytes: First address bytes
        """
        return IntegerUtils.ToBytes((hdr_type << 4) + net_tag)


class AdaShelleyAddrDecoder(IAddrDecoder):
    """
    Cardano Shelley address decoder class.
    It allows the Cardano Shelley address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano Shelley address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public keys hash bytes (public key + public staking key)

        Raises:
            ValueError: If the address encoding is not valid
        """
        for net_tag, hrp in AdaShelleyAddrConst.NETWORK_TAG_TO_ADDR_HRP.items():
            try:
                addr_dec_bytes = Bech32Decoder.Decode(hrp, addr)
            except Bech32ChecksumError as ex:
                raise ValueError("Invalid bech32 checksum") from ex
            else:
                AddrDecUtils.ValidateLength(addr_dec_bytes,
                                            (AdaShelleyAddrConst.HASH_BYTE_LEN * 2) + 1)
                got_hdr_tag, got_net_tag = _AdaShelleyAddrUtils.DecodeFirstAddrByte(addr_dec_bytes[0])

                # Check header type
                if got_hdr_tag != AdaShelleyAddrHeaderTypes.PAYMENT:
                    raise ValueError(f"Invalid header type ({got_hdr_tag})")
                # Check network tag
                if got_net_tag != net_tag:
                    raise ValueError(f"Invalid network tag  ({got_net_tag})")

                return addr_dec_bytes

        raise ValueError("Invalid address encoding")


class AdaShelleyAddrEncoder(IAddrEncoder):
    """
    Cardano Shelley address encoder class.
    It allows the Cardano Shelley address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Cardano Shelley address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            pub_skey (bytes or IPublicKey)     : Public staking key bytes or object
            net_tag (AdaShelleyAddrNetworkTags): Network tag (default: main net)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        pub_skey = kwargs["pub_skey"]
        net_tag = kwargs.get("net_tag", AdaShelleyAddrNetworkTags.MAINNET)

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)
        pub_skey_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_skey)

        # Compute keys hash
        pub_key_hash = _AdaShelleyAddrUtils.KeyHash(pub_key_obj.RawCompressed().ToBytes()[1:])
        pub_skey_hash = _AdaShelleyAddrUtils.KeyHash(pub_skey_obj.RawCompressed().ToBytes()[1:])
        # Get first byte
        first_byte = _AdaShelleyAddrUtils.EncodeFirstAddrByte(AdaShelleyAddrHeaderTypes.PAYMENT, net_tag)

        # Encode to bech32
        return Bech32Encoder.Encode(AdaShelleyAddrConst.NETWORK_TAG_TO_ADDR_HRP[net_tag],
                                    first_byte + pub_key_hash + pub_skey_hash)


class AdaShelleyRewardAddrDecoder(IAddrDecoder):
    """
    Cardano Shelley reward address decoder class.
    It allows the Cardano Shelley reward address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano Shelley address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public keys hash bytes (public key + public staking key)

        Raises:
            ValueError: If the address encoding is not valid
        """
        for net_tag, hrp in AdaShelleyAddrConst.NETWORK_TAG_TO_REWARD_ADDR_HRP.items():
            try:
                addr_dec_bytes = Bech32Decoder.Decode(hrp, addr)
            except Bech32ChecksumError as ex:
                raise ValueError("Invalid bech32 checksum") from ex
            else:
                AddrDecUtils.ValidateLength(addr_dec_bytes,
                                            AdaShelleyAddrConst.HASH_BYTE_LEN + 1)
                got_hdr_tag, got_net_tag = _AdaShelleyAddrUtils.DecodeFirstAddrByte(addr_dec_bytes[0])

                # Check header type
                if got_hdr_tag != AdaShelleyAddrHeaderTypes.REWARD:
                    raise ValueError(f"Invalid header type ({got_hdr_tag})")
                # Check network tag
                if got_net_tag != net_tag:
                    raise ValueError(f"Invalid network tag  ({got_net_tag})")

                return addr_dec_bytes

        raise ValueError("Invalid address encoding")


class AdaShelleyRewardAddrEncoder(IAddrEncoder):
    """
    Cardano Shelley reward address encoder class.
    It allows the Cardano Shelley reward address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Cardano Shelley reward address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            net_tag (AdaShelleyAddrNetworkTags): Network tag (default: main net)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        net_tag = kwargs.get("net_tag", AdaShelleyAddrNetworkTags.MAINNET)

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)

        # Compute keys hash
        pub_key_hash = _AdaShelleyAddrUtils.KeyHash(pub_key_obj.RawCompressed().ToBytes()[1:])
        # Get first byte
        first_byte = _AdaShelleyAddrUtils.EncodeFirstAddrByte(AdaShelleyAddrHeaderTypes.REWARD, net_tag)

        # Encode to bech32
        return Bech32Encoder.Encode(AdaShelleyAddrConst.NETWORK_TAG_TO_REWARD_ADDR_HRP[net_tag],
                                    first_byte + pub_key_hash)


class AdaShelleyAddr(AdaShelleyAddrEncoder):
    """
    Cardano Shelley address class.
    Only kept for compatibility, AdaShelleyAddrEncoder shall be used instead.
    """


class AdaShelleyRewardAddr(AdaShelleyRewardAddrEncoder):
    """
    Cardano Shelley reward address class.
    Only kept for compatibility, AdaShelleyRewardAddrEncoder shall be used instead.
    """
