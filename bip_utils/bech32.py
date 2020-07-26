# Copyright (c) 2017 Pieter Wuille, 2020 Emanuele Bellocchia
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
#
# NOTE: the code comes from https://github.com/sipa/bech32/tree/master/ref/python
# and it was refactored to be compliant with the other code files


# Imports
from .bech32_ex import Bech32ChecksumError, Bech32FormatError
from .          import utils


class Bech32Const:
    """ Class container for Bech32 constants. """

    # Character set
    CHARSET           = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    # Separator
    SEPARATOR         = "1"
    # Maximum string length
    MAX_STR_LEN       = 90
    # Data part minimum length
    MIN_DATA_PART_LEN = 7
    # Checkum minimum length
    CHECKSUM_LEN      = 6


class Bech32Utils:
    """ Class container for Bech32 utility functions. """

    @staticmethod
    def PolyMod(values):
        """ Computes the Bech32 checksum.

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

    @staticmethod
    def VerifyChecksum(hrp, data):
        """ Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str): HRP
            data (str): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        return Bech32Utils.PolyMod(Bech32Utils.HrpExpand(hrp) + data) == 1

    @staticmethod
    def ComputeChecksum(hrp, data):
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Computed checksum
        """

        values = Bech32Utils.HrpExpand(hrp) + data
        polymod = Bech32Utils.PolyMod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 0x1f for i in range(Bech32Const.CHECKSUM_LEN)]


class Bech32Encoder:
    """ Bech32 encoder class. It provides methods for encoding to Bech32 format. """

    @staticmethod
    def EncodeAddr(hrp, wit_ver, wit_prog):
        """ Encode a segwit address.

        Args:
            hrp (str)       : HRP
            wit_ver (int)   : Witness version
            wit_prog (bytes): Witness program

        Returns:
            str: Encoded address
        """

        # Convert to base32
        base32_enc = utils.ConvertToBits(wit_prog, 8, 5)
        if base32_enc == None:
            raise Bech32FormatError("Invalid data, cannot perform base32 conversion")

        # Encode
        return Bech32Encoder.__Encode(hrp, [wit_ver] + base32_enc)

    @staticmethod
    def __Encode(hrp, data):
        """ Encode a Bech32 string from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Encoded data
        """

        # Add checksum to data
        data += Bech32Utils.ComputeChecksum(hrp, data)
        # Encode to alphabet
        return hrp + Bech32Const.SEPARATOR + "".join([Bech32Const.CHARSET[d] for d in data])


class Bech32Decoder:
    """ Bech32 decoder class. It provides methods for decoding Bech32 format. """

    @staticmethod
    def DecodeAddr(hrp, addr):
        """ Decode a segwit address.
        Bech32FormatError is raised if the address is not valid.

        Args:
            hrp (str) : Human readable part
            addr (str): Address

        Returns:
            tuple: Witness version (index 0) and witness program (index 1)
        """

        # Decode string
        hrpgot, data = Bech32Decoder.__Decode(addr)
        # Check HRP
        if hrpgot != hrp:
            raise Bech32FormatError("Invalid segwit address (HRP not valid)")

        # Convert back from base32
        base32_dec = utils.ConvertToBits(data[1:], 5, 8, False)
        if base32_dec == None:
            raise Bech32FormatError("Invalid data, cannot perform base32 conversion")

        # Check decoded data
        if len(base32_dec) < 2 or len(base32_dec) > 40:
            raise Bech32FormatError("Invalid segwit address (length not valid)")
        if data[0] > 16:
            raise Bech32FormatError("Invalid segwit address (witness version not valid)")
        if data[0] == 0 and len(base32_dec) != 20 and len(base32_dec) != 32:
            raise Bech32FormatError("Invalid segwit address (length not valid)")

        return (data[0], utils.ListToBytes(base32_dec))

    @staticmethod
    def __Decode(bech_str):
        """ Decode and validate a Bech32 string, determining its HRP and data.

        Args:
            bech_str (str): Bech32 string

        Returns:
            tuple: HRP (index 0) and data part (index 1)

        Raises:
            Bech32FormatError: If the string is not valid
            Bech32ChecksumError: If the checksum is not valid
        """

        # Check string length and case
        if len(bech_str) > Bech32Const.MAX_STR_LEN or utils.IsStringMixed(bech_str):
            raise Bech32FormatError("Invalid bech32 string (length not valid)")

        # Lower string
        bech_str = bech_str.lower()

        # Find separator and check its position
        sep_pos = bech_str.rfind(Bech32Const.SEPARATOR)
        if sep_pos == -1:
            raise Bech32FormatError("Invalid bech32 string (no separator found)")

        # Get HRP and check it
        hrp = bech_str[:sep_pos]
        if len(hrp) == 0 or any(ord(x) < 33 or ord(x) > 126 for x in hrp):
            raise Bech32FormatError("Invalid bech32 string (HRP not valid)")

        # Get data and check it
        data_part = bech_str[sep_pos + 1:]
        if len(data_part) < Bech32Const.MIN_DATA_PART_LEN or not all(x in Bech32Const.CHARSET for x in data_part):
            raise Bech32FormatError("Invalid bech32 string (data part not valid)")

        # Convert back from alphabet and verify checksum
        int_data = [Bech32Const.CHARSET.find(x) for x in data_part]
        if not Bech32Utils.VerifyChecksum(hrp, int_data):
            raise Bech32ChecksumError("Invalid checksum")

        # Remove checksum from data
        return (hrp, int_data[:-Bech32Const.CHECKSUM_LEN])
