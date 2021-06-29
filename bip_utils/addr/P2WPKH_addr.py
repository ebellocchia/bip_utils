# Copyright (c) 2021 Emanuele Bellocchia
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
from bip_utils.addr.utils import AddrUtils
from bip_utils.bech32 import SegwitBech32Encoder
from bip_utils.conf import Bip84BitcoinMainNet
from bip_utils.ecc import Secp256k1PublicKey
from bip_utils.utils import CryptoUtils


class P2WPKHAddr:
    """ P2WPKH class. It allows the Pay-to-Witness-Public-Key-Hash address generation.
    Refer to:
    https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, Secp256k1PublicKey],
                  wit_ver: int = Bip84BitcoinMainNet.AddrConfKey("wit_ver"),
                  net_addr_ver: str = Bip84BitcoinMainNet.AddrConfKey("net_ver")) -> str:
        """ Get address in P2WPKH format.

        Args:
            pub_key (bytes or Secp256k1PublicKey): Public key bytes or object
            wit_ver (int, optional))             : Witness version
            net_addr_ver (str, optional)         : Net address version, default is Bitcoin main network

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        pub_key_obj = AddrUtils.ValidateAndGetSecp256k1Key(pub_key)

        return SegwitBech32Encoder.Encode(net_addr_ver,
                                          wit_ver,
                                          CryptoUtils.Hash160(pub_key_obj.RawCompressed().ToBytes()))
