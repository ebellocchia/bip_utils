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

# Refer to:
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

# Imports
import binascii
from . import utils
from .bech32 import Bech32Encoder

class P2WPKHConst:
    """ Class container for P2WPKH constants. """

    # Main net address HRP
    MAINNET_ADDR_HRP = "bc"
    # Test net address HRP
    TESTNET_ADDR_HRP = "tb"
    # Witness version
    WITNESS_VER      = 0


class P2WPKH:
    """ P2WPKH class. It allows the Pay-to-Witness-Public-Key-Hash address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes, is_testnet = False):
        """ Get address in P2WPKH format.

        Args:
            pub_key_bytes (bytes)       : public key bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """

        # Get address HRP
        addr_hrp = P2WPKHConst.MAINNET_ADDR_HRP if not is_testnet else P2WPKHConst.TESTNET_ADDR_HRP
        # Witness program is the Hash160 of the public key
        wit_prog = utils.Hash160(pub_key_bytes)

        # Combine it with witness version and HRP
        return Bech32Encoder.EncodeAddr(addr_hrp, P2WPKHConst.WITNESS_VER, wit_prog)
