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
from bip_utils.bech32.bech32           import Bech32EncoderBase, Bech32Utils
from bip_utils.bech32.segwit_bech32    import SegwitBech32Const, SegwitBech32Utils
from bip_utils.utils                   import ConvUtils


class AtomBech32Const:
    # Separator (same as Segwit)
    SEPARATOR = SegwitBech32Const.SEPARATOR


class AtomBech32Encoder(Bech32EncoderBase):
    """ Segwit encoder class. It provides methods for encoding to Segwit format. """

    @staticmethod
    def Encode(hrp, data):
        """ Encode a segwit address.

        Args:
            hrp (str)       : HRP
            wit_prog (bytes): Data

        Returns:
            str: Encoded address

        Raises:
            Bech32FormatError: If the data is not valid
        """

        return AtomBech32Encoder._EncodeBech32(hrp, Bech32Utils.ConvertToBase32(data), AtomBech32Const.SEPARATOR)

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
