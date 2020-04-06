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
import binascii
from .              import utils
from .base58        import Base58Encoder
from .bip_coin_conf import BitcoinConf


class P2SHConst:
    """ Class container for P2SH constants. """

    # Script bytes
    SCRIPT_BYTES         = b"0014"


class P2SH:
    """ P2SH class. It allows the Pay-to-Script-Hash address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes, net_addr_ver = BitcoinConf.P2SH_NET_VER["main"]):
        """ Get address in P2SH format.

        Args:
            pub_key_bytes (bytes)       : public key bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (str):
            Address string
        """

        # Key hash: Hash160(public_key)
        key_hash = utils.Hash160(pub_key_bytes)
        # Script signature: 0x0014 | Hash160(public_key)
        script_sig = binascii.unhexlify(P2SHConst.SCRIPT_BYTES) + key_hash
        # Address bytes = Hash160(script_signature)
        addr_bytes = utils.Hash160(script_sig)

        # Final address: Base58Check(addr_prefix | address_bytes)
        return Base58Encoder.CheckEncode(net_addr_ver + addr_bytes)

