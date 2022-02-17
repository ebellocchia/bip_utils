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

"""Module for Ethereum address computation."""

# Imports
from typing import Any, Union
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import ConvUtils, CryptoUtils


class EthAddrConst:
    """Class container for Ethereum address constants."""

    # Start byte
    START_BYTE: int = 24
    # Address length
    ADDR_LEN: int = 40


class _EthAddrUtils:
    """Class container for Ethereum address utility functions."""

    @staticmethod
    def ChecksumEncode(addr: str) -> str:
        """
        Checksum encode the specified address.

        Args:
            addr (str): Address string

        Returns:
            str: Checksum encoded address
        """

        # Compute address digest
        addr_hex_digest = ConvUtils.BytesToHexString(CryptoUtils.Kekkak256(addr.lower()))
        # Encode it
        enc_addr = [c.upper() if (int(addr_hex_digest[i], 16) >= 8) else c.lower() for i, c in enumerate(addr)]

        return "".join(enc_addr)


class EthAddr(IAddrDecoder, IAddrEncoder):
    """
    Ethereum address class.
    It allows the Ethereum address encoding/decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode an Algorand address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public key hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """

        # Check prefix
        prefix = CoinsConf.Ethereum.Params("addr_prefix")
        prefix_got = addr[:len(prefix)]
        if prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected {prefix}, got {prefix_got}")
        # Remove it
        addr_no_prefix = addr[len(prefix):]
        # Check length
        if len(addr_no_prefix) != EthAddrConst.ADDR_LEN:
            raise ValueError(f"Invalid length {len(addr_no_prefix)}")
        # Check checksum encoding
        print("addr_no_prefix", addr_no_prefix, _EthAddrUtils.ChecksumEncode(addr_no_prefix))
        if addr_no_prefix != _EthAddrUtils.ChecksumEncode(addr_no_prefix):
            raise ValueError("Invalid checksum encode")

        return ConvUtils.HexStringToBytes(addr_no_prefix)

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Ethereum address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs                     : Not used

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)

        # First byte of the uncompressed key (i.e. 0x04) is not needed
        kekkak_hex = ConvUtils.BytesToHexString(CryptoUtils.Kekkak256(pub_key_obj.RawUncompressed().ToBytes()[1:]))
        addr = kekkak_hex[EthAddrConst.START_BYTE:]
        return CoinsConf.Ethereum.Params("addr_prefix") + _EthAddrUtils.ChecksumEncode(addr)
