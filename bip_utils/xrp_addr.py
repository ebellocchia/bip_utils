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
import sha3
from .base58        import Base58Const
from .bip_coin_conf import RippleConf
from .P2PKH         import P2PKH


class XrpAddrConst:
    """ Class container for Ripple address constants. """

    # Prefix
    ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


class XrpAddr:
    """ Ripple address class. It allows the Ripple address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes):
        """ Get address in Ripple format.
        ValueError is raised (by P2PKH module) if key is not a public compressed key.

        Args:
            pub_key_bytes (bytes) : public key bytes

        Returns (str):
            Address string
        """

        # The Ripple address is just the P2PKH address with a different alphabet
        addr = P2PKH.ToAddress(pub_key_bytes, RippleConf.P2PKH_NET_VER)
        # Just substitute the characters with the new alphabet
        xrp_addr = [XrpAddrConst.ALPHABET[Base58Const.ALPHABET.index(c)] for c in addr]

        return "".join(xrp_addr)
