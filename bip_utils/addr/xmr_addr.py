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
from typing import Any, Union
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.addr.utils import AddrUtils
from bip_utils.base58 import Base58XmrEncoder
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils


class XmrAddrConst:
    """ Class container for Monero address constants. """

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 4


class XmrAddr(IAddrEncoder):
    """ Monero address class. It allows the Monero address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get address in Monero format.

        Args:
            pub_key (bytes or IPublicKey): Public spend key bytes or object

        Other Parameters:
            pub_view_key (bytes or IPublicKey): Public view key bytes or object
            net_ver (bytes)                   : Net version

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519-monero
        """
        pub_view_key = kwargs["pub_view_key"]
        net_ver = kwargs["net_ver"]

        pub_spend_key_obj = AddrUtils.ValidateAndGetEd25519MoneroKey(pub_key)
        pub_view_key_obj = AddrUtils.ValidateAndGetEd25519MoneroKey(pub_view_key)

        data = net_ver + pub_spend_key_obj.RawCompressed().ToBytes() + pub_view_key_obj.RawCompressed().ToBytes()
        checksum = CryptoUtils.Kekkak256(data)

        return Base58XmrEncoder.Encode(data + checksum[:XmrAddrConst.CHECKSUM_BYTE_LEN])
