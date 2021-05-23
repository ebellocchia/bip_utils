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
from bip_utils.bech32 import SegwitBech32Encoder
from bip_utils.conf import BitcoinConf
from bip_utils.ecc import EcdsaPublicKey, Secp256k1
from bip_utils.utils import CryptoUtils


class P2WPKHConst:
    """ Class container for P2WPKH constants. """

    # Witness version
    WITNESS_VER: int = 0


class P2WPKH:
    """ P2WPKH class. It allows the Pay-to-Witness-Public-Key-Hash address generation.
    Refer to:
    https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    """

    @staticmethod
    def ToAddress(pub_key: Union[bytes, EcdsaPublicKey],
                  net_addr_ver: str = BitcoinConf.P2WPKH_NET_VER.Main()) -> str:
        """ Get address in P2WPKH format.

        Args:
            pub_key (bytes or EcdsaPublicKey): Public key bytes or object
            net_addr_ver (str, optional)     : Net address version, default is Bitcoin main network

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
        """
        if isinstance(pub_key, bytes):
            pub_key = Secp256k1.PublicKeyFromBytes(pub_key)

        return SegwitBech32Encoder.Encode(net_addr_ver,
                                          P2WPKHConst.WITNESS_VER,
                                          CryptoUtils.Hash160(pub_key.RawCompressed().ToBytes()))
