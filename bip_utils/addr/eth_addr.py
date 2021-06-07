# Copyright (c) 2020 Emanuele Bellocchia
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


# Imports
from typing import Union
from bip_utils.addr.utils import AddrUtils
from bip_utils.ecc import Secp256k1PublicKey
from bip_utils.utils import ConvUtils, CryptoUtils


class EthAddrConst:
    """ Class container for Ethereum address constants. """

    # Prefix
    PREFIX: str = "0x"
    # Start byte
    START_BYTE: int = 24


class EthAddrUtils:
    """ Class container for Ethereum address utility functions. """

    @staticmethod
    def ChecksumEncode(addr: str) -> str:
        """ Checksum encode the specified address.

        Args:
            addr (str): Address string

        Returns:
            str: Checksum encoded address
        """

        # Compute address digest
        addr_hex_digest = ConvUtils.BytesToHexString(CryptoUtils.Kekkak256(addr))
        # Encode it
        enc_addr = [c.upper() if (int(addr_hex_digest[i], 16) >= 8) else c.lower() for i, c in enumerate(addr)]

        return "".join(enc_addr)


class EthAddr:
    """ Ethereum address class. It allows the Ethereum address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, Secp256k1PublicKey]) -> str:
        """ Get address in Ethereum format.

        Args:
            pub_key (bytes or Secp256k1PublicKey): Public key bytes or object

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        pub_key = AddrUtils.ValidateAndGetSecp256k1Key(pub_key)

        # First byte of the uncompressed key (i.e. 0x04) is not needed
        key_hex_digest = ConvUtils.BytesToHexString(CryptoUtils.Kekkak256(pub_key.RawUncompressed().ToBytes()[1:]))
        addr = key_hex_digest[EthAddrConst.START_BYTE:]
        return EthAddrConst.PREFIX + EthAddrUtils.ChecksumEncode(addr)
