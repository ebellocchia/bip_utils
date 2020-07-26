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
from .bech32_ex import Bech32ChecksumError, Bech32FormatError
from .bech32    import Bech32Decoder, Bech32Encoder, Bech32Utils
from .          import utils


class BchBech32Const:
    """ Class container for Bitcoin Cash constants. """

    # Separator
    SEPARATOR    = ":"
    # Checkum minimum length
    CHECKSUM_LEN = 8


class BchBech32Utils:
    """ Class container for Bitcoin Cash utility functions. """

    @staticmethod
    def PolyMod(values):
        """ Computes the Bitcoin Cash checksum.

        Args:
            values (list): Values for checksum computation

        Returns:
            int: Computed checksum
        """

        chk = 1
        generator = [
            (0x01, 0x98f2bc8e61),
            (0x02, 0x79b76d99e2),
            (0x04, 0xf33e5fb3c4),
            (0x08, 0xae2eabe2a8),
            (0x10, 0x1e4f43e470)]

        for value in values:
            top = chk >> 35
            chk = ((chk & 0x07ffffffff) << 5) ^ value
            for i in generator:
                if top & i[0] != 0:
                    chk ^= i[1]

        return chk ^ 1

    @staticmethod
    def HrpExpand(hrp):
        """ Expand the HRP into values for checksum computation.

        Args:
            hrp (str): HRP

        Returns:
            list: Expanded HRP
        """
        return [ord(x) & 0x1f for x in hrp] + [0]


class BchBech32Encoder(Bech32Encoder):
    """ Bitcoin Cash encoder class. It provides methods for encoding to Bitcoin Cash format. """

    @staticmethod
    def Encode(hrp, net_ver, data):
        """ Encode a Bitcoin Cash address.

        Args:
            hrp (str)      : HRP
            net_ver (bytes): Net version
            data (bytes)   : Data

        Returns:
            str: Encoded address

        Raises:
            Bech32FormatError: If the data is not valid
        """

        return BchBech32Encoder._Encode(hrp, Bech32Utils.ConvertToBase32(net_ver + data), BchBech32Const.SEPARATOR)

    @staticmethod
    def _ComputeChecksum(hrp, data):
        """ Compute the checksum from the specified HRP and data.

        Args:
            hrp (str)  : HRP
            data (list): Data part

        Returns:
            str: Computed checksum
        """

        values = BchBech32Utils.HrpExpand(hrp) + data
        polymod = BchBech32Utils.PolyMod(values + [0, 0, 0, 0, 0, 0, 0, 0])
        return [(polymod >> 5 * (7 - i)) & 0x1f for i in range(BchBech32Const.CHECKSUM_LEN)]
