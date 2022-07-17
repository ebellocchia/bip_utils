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

"""Module for Cardano V3 address encoding/decoding."""

# Imports
from enum import IntEnum, unique
from typing import Any, Dict, Union
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils, IntegerUtils


@unique
class AdaV3AddrNetworkTags(IntEnum):
    """Enumerative for Cardano V2 network tags."""

    TESTNET = 0
    MAINNET = 1


class AdaV3AddrConst:
    """Class container for Cardano V3 address constants."""

    # Hash length in bytes
    HASH_BYTE_LEN: int = 28
    # Header type
    HEADER_TYPE: int = 0
    # Network tag to HRP
    NETWORK_TAG_TO_HRP: Dict[AdaV3AddrNetworkTags, str] = {
        AdaV3AddrNetworkTags.MAINNET: CoinsConf.CardanoMainNet.Params("addr_hrp"),
        AdaV3AddrNetworkTags.TESTNET: CoinsConf.CardanoTestNet.Params("addr_hrp"),
    }


class AdaV3AddrDecoder(IAddrDecoder):
    """
    Cardano V3 address decoder class.
    It allows the Cardano V3 address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Cardano V3 address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public keys hash bytes (public key + public staking key)

        Raises:
            ValueError: If the address encoding is not valid
        """
        for net_tag, hrp in AdaV3AddrConst.NETWORK_TAG_TO_HRP.items():
            try:
                addr_dec_bytes = Bech32Decoder.Decode(hrp, addr)
            except Bech32ChecksumError as ex:
                raise ValueError("Invalid bech32 checksum") from ex
            else:
                AddrDecUtils.ValidateLength(addr_dec_bytes,
                                            (AdaV3AddrConst.HASH_BYTE_LEN * 2) + 1)
                # Check header type
                if addr_dec_bytes[0] >> 4 != AdaV3AddrConst.HEADER_TYPE:
                    raise ValueError(f"Invalid header type ({addr_dec_bytes[0]})")
                # Check network tag
                if addr_dec_bytes[0] & 0x0F != net_tag:
                    raise ValueError(f"Invalid network tag  ({addr_dec_bytes[0]})")

                return addr_dec_bytes

        raise ValueError("Invalid address encoding")


class AdaV3AddrEncoder(IAddrEncoder):
    """
    Cardano V3 address encoder class.
    It allows the Cardano V3 address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Cardano address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            pub_skey (bytes or IPublicKey): Public staking key bytes or object
            net_tag (AdaV3AddrNetworkTags): Network tag (default: main net)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        pub_skey = kwargs["pub_skey"]
        net_tag = kwargs.get("net_tag", AdaV3AddrNetworkTags.MAINNET)

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)
        pub_skey_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_skey)

        # Compute keys hash
        pub_key_hash = CryptoUtils.Blake2b(pub_key_obj.RawCompressed().ToBytes()[1:],
                                           AdaV3AddrConst.HASH_BYTE_LEN)
        pub_skey_hash = CryptoUtils.Blake2b(pub_skey_obj.RawCompressed().ToBytes()[1:],
                                            AdaV3AddrConst.HASH_BYTE_LEN)
        # Get first byte
        first_byte = (AdaV3AddrConst.HEADER_TYPE << 4) + net_tag

        # Encode to bech32
        return Bech32Encoder.Encode(AdaV3AddrConst.NETWORK_TAG_TO_HRP[net_tag],
                                    IntegerUtils.ToBytes(first_byte) + pub_key_hash + pub_skey_hash)


class AdaV3Addr(AdaV3AddrEncoder):
    """
    Cardano V3 address class.
    Only kept for compatibility, AdaV3AddrEncoder shall be used instead.
    """
