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

"""Module for Neo address computation."""

# Imports
from typing import Any, Union
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import ConvUtils, CryptoUtils


class NeoAddrConst:
    """Class container for NEO address constants."""

    # Address prefix
    PREFIX: bytes = b"\x21"
    # Address suffix
    SUFFIX: bytes = b"\xac"
    # Address length in bytes
    ADDR_BYTE_LEN: int = 21


class NeoAddr(IAddrDecoder, IAddrEncoder):
    """
    Neo address class.
    It allows the Neo address encoding/decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Neo address to bytes.

        Args:
            addr (str): Address string

        Other Parameters:
            ver (bytes): Version

        Returns:
            bytes: Public key hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """
        ver = kwargs["ver"]

        # Decode from base58
        addr_dec = Base58Decoder.CheckDecode(addr)
        # Validate length
        AddrDecUtils.ValidateLength(addr_dec, NeoAddrConst.ADDR_BYTE_LEN)
        # Check version
        ver_got = ConvUtils.IntegerToBytes(addr_dec[0])
        if ver != ver_got:
            raise ValueError(f"Invalid version (expected {ConvUtils.BytesToHexString(ver)}, "
                             f"got {ConvUtils.BytesToHexString(ver_got)}")

        return addr_dec[1:]

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Neo address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            ver (bytes): Version

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        ver = kwargs["ver"]

        pub_key_obj = AddrKeyValidator.ValidateAndGetNist256p1Key(pub_key)

        # Get payload
        payload = (NeoAddrConst.PREFIX
                   + pub_key_obj.RawCompressed().ToBytes()
                   + NeoAddrConst.SUFFIX)
        # Encode to base58
        return Base58Encoder.CheckEncode(ver + CryptoUtils.Hash160(payload))
