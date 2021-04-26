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

# Specifications:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

# Imports
from enum import Enum, auto, unique
from typing import Dict, List
from bip_utils.bech32.bech32_base import Bech32DecoderBase, Bech32EncoderBase
from bip_utils.bech32.atom_bech32 import AtomBech32Decoder, AtomBech32Encoder


@unique
class AvaxChainTypes(Enum):
    """ Enumerative for Avax chains. """

    AVAX_X_CHAIN = auto(),
    AVAX_P_CHAIN = auto(),


class AvaxBech32Const:
    """ Class container for Avax Bech32 constants. """

    # Human readable aprt
    HRP: str = "avax"

    # Prefixes for chains
    CHAIN_PREFIXES: Dict[AvaxChainTypes, str] = {
        AvaxChainTypes.AVAX_X_CHAIN: "X-",
        AvaxChainTypes.AVAX_P_CHAIN: "P-",
    }


class AvaxBech32Encoder(Bech32EncoderBase):
    """ Avax Bech32 encoder class. It provides methods for encoding to Avax Bech32 format.
    Same as Atom Bech32 encoder.
    """

    @staticmethod
    def Encode(data: bytes,
               chain_type: AvaxChainTypes) -> str:
        """ Encode to Atom Bech32.

        Args:
            data (bytes)               : Data
            chain_type (AvaxChainTypes): Chain type

        Returns:
            str: Encoded address

        Raises:
            Bech32FormatError: If the data is not valid
        """

        # Same as Atom with prefix
        return AvaxBech32Const.CHAIN_PREFIXES[chain_type] + AtomBech32Encoder.Encode(AvaxBech32Const.HRP, data)

    @staticmethod
    def _ComputeChecksum(hrp: str,
                         data: List[int]) -> List[int]:
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            list: Computed checksum
        """
        # Nothing to do, the Atom one is used
        pass


class AvaxBech32Decoder(Bech32DecoderBase):
    """ Avax decoder class. It provides methods for decoding Avax format. """

    @staticmethod
    def Decode(addr: str) -> bytes:
        """ Decode from Avax Bech32.

        Args:
            hrp (str) : Human readable part
            addr (str): Address

        Returns:
            bytes: Data

        Raises:
            AvaxBech32FormatError: If the address is not valid
            Bech32FormatError: If the bech32 string is not valid
            Bech32ChecksumError: If the checksum is not valid
        """

        # Check prefix
        if (not addr.startswith(AvaxBech32Const.CHAIN_PREFIXES[AvaxChainTypes.AVAX_P_CHAIN]) and
                not addr.startswith(AvaxBech32Const.CHAIN_PREFIXES[AvaxChainTypes.AVAX_X_CHAIN])):
            raise AvaxBech32FormatError("Invalid Avax format (prefix not valid)")

        # Remove Avax prefix
        return AtomBech32Decoder.Decode(AvaxBech32Const.HRP, addr[2:])

    @staticmethod
    def _VerifyChecksum(hrp: str,
                        data: List[int]) -> bool:
        """ Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str) : HRP
            data (list): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        # Nothing to do, the Atom one is used
        pass
