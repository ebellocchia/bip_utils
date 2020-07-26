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
from .bech32_ex import Bech32ChecksumError, Bech32FormatError
from .bech32    import Bech32Decoder, Bech32Encoder, Bech32Utils
from .segwit_ex import SegwitAddressError
from .          import utils


class SegwitConst:
    """ Class container for Segwit constants. """

    # Separator
    SEPARATOR                 = "1"
    # Checkum minimum length
    CHECKSUM_LEN              = 6
    # Witness version maximum value
    WITNESS_VER_MAX_VAL       = 16
    # Minimum data length
    DATA_MIN_LEN              = 2
    # Maximum data length
    DATA_MAX_LEN              = 40
    # Accepted data lengths when witness version is zero
    WITNESS_VER_ZERO_DATA_LEN = (20, 32)


class SegwitUtils:
    """ Class container for Segwit utility functions. """

    @staticmethod
    def PolyMod(values):
        """ Computes the Segwit checksum.

        Args:
            values (list): Values for checksum computation

        Returns:
            int: Computed checksum
        """

        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    @staticmethod
    def HrpExpand(hrp):
        """ Expand the HRP into values for checksum computation.

        Args:
            hrp (str): HRP

        Returns:
            list: Expanded HRP
        """
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 0x1f for x in hrp]


class SegwitEncoder(Bech32Encoder):
    """ Segwit encoder class. It provides methods for encoding to Segwit format. """

    @staticmethod
    def EncodeAddr(hrp, wit_ver, wit_prog):
        """ Encode a segwit address.

        Args:
            hrp (str)       : HRP
            wit_ver (int)   : Witness version
            wit_prog (bytes): Witness program

        Returns:
            str: Encoded address

        Raises:
            SegwitAddressError: If the string is not valid
        """

        return SegwitEncoder._Encode(hrp, [wit_ver] + Bech32Utils.ConvertToBase32(wit_prog), SegwitConst.SEPARATOR)

    @staticmethod
    def _ComputeChecksum(hrp, data):
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Computed checksum
        """

        values = SegwitUtils.HrpExpand(hrp) + data
        polymod = SegwitUtils.PolyMod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 0x1f for i in range(SegwitConst.CHECKSUM_LEN)]


class SegwitDecoder(Bech32Decoder):
    """ Segwit decoder class. It provides methods for decoding Segwit format. """

    @staticmethod
    def DecodeAddr(hrp, addr):
        """ Decode a segwit address.

        Args:
            hrp (str) : Human readable part
            addr (str): Address

        Returns:
            tuple: Witness version (index 0) and witness program (index 1)

        Raises:
            SegwitAddressError: If the string is not valid
            Bech32FormatError: If the string is not valid
            Bech32ChecksumError: If the checksum is not valid
        """

        # Decode string
        hrpgot, data = SegwitDecoder._Decode(addr, SegwitConst.SEPARATOR, SegwitConst.CHECKSUM_LEN)
        # Check HRP
        if hrpgot != hrp:
            raise SegwitAddressError("Invalid segwit address (HRP not valid, expected %s, got %s)" % (hrp, hrpgot))

        # Convert back from base32
        conv_data = Bech32Utils.ConvertFromBase32(data[1:])

        # Check decoded data
        if len(conv_data) < SegwitConst.DATA_MIN_LEN or len(conv_data) > SegwitConst.DATA_MAX_LEN:
            raise SegwitAddressError("Invalid segwit address (length not valid)")
        if data[0] > SegwitConst.WITNESS_VER_MAX_VAL:
            raise SegwitAddressError("Invalid segwit address (witness version not valid)")
        if data[0] == 0 and not len(conv_data) in SegwitConst.WITNESS_VER_ZERO_DATA_LEN:
            raise SegwitAddressError("Invalid segwit address (length not valid)")

        return (data[0], utils.ListToBytes(conv_data))

    @staticmethod
    def _VerifyChecksum(hrp, data):
        """ Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str): HRP
            data (str): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        return SegwitUtils.PolyMod(SegwitUtils.HrpExpand(hrp) + data) == 1
