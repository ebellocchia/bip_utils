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

# Specifications:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

# Imports
from bip_utils.bech32.bech32_base    import Bech32DecoderBase, Bech32EncoderBase, Bech32BaseUtils
from bip_utils.bech32.segwit_bech32  import SegwitBech32Const, SegwitBech32Utils
from bip_utils.bech32.atom_bech32_ex import AtomBech32FormatError
from bip_utils.utils                 import ConvUtils


class AtomBech32Const:
    # Separator (same as Segwit)
    SEPARATOR    = SegwitBech32Const.SEPARATOR
    # Checkum length (same as Segwit)
    CHECKSUM_LEN = SegwitBech32Const.CHECKSUM_LEN
    # Minimum data length
    DATA_MIN_LEN = 2
    # Maximum data length
    DATA_MAX_LEN = 40


class AtomBech32Encoder(Bech32EncoderBase):
    """ Atom encoder class. It provides methods for encoding to Atom format. """

    @staticmethod
    def Encode(hrp, data):
        """ Encode to Atom Bech32.

        Args:
            hrp (str)       : HRP
            wit_prog (bytes): Data

        Returns:
            str: Encoded address

        Raises:
            Bech32FormatError: If the data is not valid
        """

        return AtomBech32Encoder._EncodeBech32(hrp, Bech32BaseUtils.ConvertToBase32(data), AtomBech32Const.SEPARATOR)

    @staticmethod
    def _ComputeChecksum(hrp, data):
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Computed checksum
        """

        # Same as Segwit
        return SegwitBech32Utils.ComputeChecksum(hrp, data)


class AtomBech32Decoder(Bech32DecoderBase):
    """ Atom decoder class. It provides methods for decoding Atom format. """

    @staticmethod
    def Decode(hrp, addr):
        """ Decode from Atom Bech32.

        Args:
            hrp (str) : Human readable part
            addr (str): Address

        Returns:
            bytes: Data

        Raises:
            AtomBech32FormatError: If the address is not valid
            Bech32FormatError: If the bech32 string is not valid
            Bech32ChecksumError: If the checksum is not valid
        """

        # Decode string
        hrpgot, data = AtomBech32Decoder._DecodeBech32(addr, AtomBech32Const.SEPARATOR, AtomBech32Const.CHECKSUM_LEN)

        # Check HRP
        if hrpgot != hrp:
            raise AtomBech32FormatError("Invalid Atom format (HRP not valid, expected %s, got %s)" % (hrp, hrpgot))

        # Convert back from base32
        conv_data = Bech32BaseUtils.ConvertFromBase32(data)

        # Check converted data
        if len(conv_data) < AtomBech32Const.DATA_MIN_LEN or len(conv_data) > AtomBech32Const.DATA_MAX_LEN:
            raise AtomBech32FormatError("Invalid Atom format (length not valid)")

        return ConvUtils.ListToBytes(conv_data)

    @staticmethod
    def _VerifyChecksum(hrp, data):
        """ Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str): HRP
            data (str): Data part

        Returns:
            bool: True if valid, false otherwise
        """

        # Same as Segwit
        return SegwitBech32Utils.VerifyChecksum(hrp, data)
