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
# NOTE: the code comes from: https://github.com/sipa/bech32/tree/master/ref/python
# and it was refactored to be compliant with the other code files


# Imports
from .bech32_ex import Bech32ChecksumError, Bech32FormatError
from .          import utils


class Bech32Const:
    """ Class container for Bech32 constants. """

    # Character set
    CHARSET   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    # Separator
    SEPARATOR = "1"


class Bech32Utils:
    """ Class container for Bech32 utility functions. """

    @staticmethod
    def ConvertToBits(data, from_bits, to_bits, pad = True):
        """ Perform generic bits conversion.

        Args:
            data    (list or bytes): Data to be converted
            from_bits (int)        : Number of bits to start from
            to_bits (int)          : Number of bits at the end
            pad    (bool)          : True if data must be padded, false otherwise

        Returns:
            list: List of converted bits
        """

        acc = 0
        bits = 0
        ret = []
        maxv = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1

        for value in data:
            if value < 0 or (value >> from_bits):
                raise Bech32FormatError("Invalid data, cannot perform base32 conversion")
            acc = ((acc << from_bits) | value) & max_acc
            bits += from_bits
            while bits >= to_bits:
                bits -= to_bits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (to_bits - bits)) & maxv)
        elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
            raise Bech32FormatError("Invalid data, cannot perform base32 conversion")
        return ret

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
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


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
        return Bech32Encoder.__Encode(hrp, [wit_ver] + Bech32Utils.ConvertToBits(wit_prog, 8, 5))

    @staticmethod
    def __Encode(hrp, data):
        """ Encode a Bech32 string from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Encoded data
        """

        combined = data + Bech32Encoder.__CreateChecksum(hrp, data)
        return hrp + Bech32Const.SEPARATOR + "".join([Bech32Const.CHARSET[d] for d in combined])

    @staticmethod
    def __CreateChecksum(hrp, data):
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Computed checksum
        """

        values = Bech32Utils.HrpExpand(hrp) + data
        polymod = Bech32Utils.PolyMod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


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

        hrpgot, data = Bech32Decoder.__Decode(addr)
        if hrpgot != hrp:
            raise Bech32FormatError("Invalid segwit address")

        decoded = Bech32Utils.ConvertToBits(data[1:], 5, 8, False)

        if len(decoded) < 2 or len(decoded) > 40:
            raise Bech32FormatError("Invalid segwit address")
        if data[0] > 16:
            raise Bech32FormatError("Invalid segwit address")
        if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
            raise Bech32FormatError("Invalid segwit address")

        return (data[0], utils.ListToBytes(decoded))

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

        if ((any(ord(x) < 33 or ord(x) > 126 for x in bech_str)) or
                (bech_str.lower() != bech_str and bech_str.upper() != bech_str)):
            raise Bech32FormatError("Invalid bech32 string")

        bech_str = bech_str.lower()
        pos = bech_str.rfind(Bech32Const.SEPARATOR)
        if pos < 1 or pos + 7 > len(bech_str) or len(bech_str) > 90:
            raise Bech32FormatError("Invalid bech32 string")
        if not all(x in Bech32Const.CHARSET for x in bech_str[pos+1:]):
            raise Bech32FormatError("Invalid bech32 string")

        hrp = bech_str[:pos]
        data = [Bech32Const.CHARSET.find(x) for x in bech_str[pos+1:]]
        if not Bech32Decoder.__VerifyChecksum(hrp, data):
            raise Bech32ChecksumError("Invalid checksum")

        return (hrp, data[:-6])

    @staticmethod
    def __VerifyChecksum(hrp, data):
        """ Verify the checksum from the specified HRP and converted data characters.

        Args:
            hrp  (str): HRP
            data (str): Data part

        Returns:
            bool: True if valid, false otherwise
        """
        return Bech32Utils.PolyMod(Bech32Utils.HrpExpand(hrp) + data) == 1
