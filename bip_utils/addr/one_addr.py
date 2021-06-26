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
from typing import Union
from bip_utils.addr.eth_addr import EthAddr
from bip_utils.ecc import Secp256k1PublicKey
from bip_utils.bech32 import Bech32Encoder
from bip_utils.conf import HarmonyOneConf
from bip_utils.utils import ConvUtils


class OneAddr:
    """ Harmony One address class. It allows the Harmony One address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, Secp256k1PublicKey]) -> str:
        """ Get address in Harmony One format.

        Args:
            pub_key (bytes or Secp256k1PublicKey): Public key bytes or object

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """

        # Get address in Ethereum format (remove "0x" at the beginning)
        eth_addr = EthAddr.EncodeKey(pub_key)[2:]

        # Encode in Bech32 format
        return Bech32Encoder.Encode(HarmonyOneConf.ADDR_HRP.Main(), ConvUtils.HexStringToBytes(eth_addr))
