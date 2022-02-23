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

"""Module for Tron address computation."""

# Imports
from typing import Any, Union
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.addr.eth_addr import EthAddrConst, EthAddr
from bip_utils.base58 import Base58ChecksumError, Base58Decoder, Base58Encoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import ConvUtils


class TrxAddr(IAddrDecoder, IAddrEncoder):
    """
    Tron address class.
    It allows the Tron address encoding/decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode a Tron address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public key hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """

        try:
            # Decode from base58
            addr_dec = Base58Decoder.CheckDecode(addr)
        except Base58ChecksumError as ex:
            raise ValueError("Invalid base58 checksum") from ex
        else:
            # Validate length
            AddrDecUtils.ValidateLength(addr_dec,
                                        (EthAddrConst.ADDR_LEN // 2) + len(CoinsConf.Tron.Params("addr_prefix")))
            # Validate and remove prefix
            addr_no_prefix = AddrDecUtils.ValidateAndRemovePrefix(addr_dec,
                                                                  CoinsConf.Tron.Params("addr_prefix"))

            return EthAddr.DecodeAddr(CoinsConf.Ethereum.Params("addr_prefix") + ConvUtils.BytesToHexString(addr_no_prefix),
                                      skip_chksum_enc=True)

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Tron address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs                     : Not used

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """

        # Get address in Ethereum format (remove "0x" at the beginning)
        eth_addr = EthAddr.EncodeKey(pub_key)[2:]
        # Add prefix and encode
        return Base58Encoder.CheckEncode(CoinsConf.Tron.Params("addr_prefix") + ConvUtils.HexStringToBytes(eth_addr))
