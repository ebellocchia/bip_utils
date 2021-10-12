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
from typing import Any, Optional, Union
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.addr.utils import AddrUtils
from bip_utils.base58 import Base58XmrEncoder
from bip_utils.coin_conf import MoneroConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils


class XmrAddrConst:
    """ Class container for Monero address constants. """

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 4
    # Payment ID length in bytes
    PAYMENT_ID_BYTE_LEN: int = 8


class XmrAddrUtils:
    """ Class container for Monero address utility functions. """

    @staticmethod
    def EncodeKeyGeneric(pub_skey: Union[bytes, IPublicKey],
                         pub_vkey: Union[bytes, IPublicKey],
                         net_ver: bytes,
                         payment_id: Optional[bytes] = None) -> str:
        """ Get address in Monero format.

        Args:
            pub_skey (bytes or IPublicKey): Public spend key bytes or object
            pub_vkey (bytes or IPublicKey): Public view key bytes or object
            net_ver (bytes)               : Net version
            payment_id (bytes, optional)  : Payment ID (only for integrated addresses)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519-monero
        """
        if payment_id is not None and len(payment_id) != XmrAddrConst.PAYMENT_ID_BYTE_LEN:
            raise ValueError("Invalid payment ID")

        payment_id = b"" if payment_id is None else payment_id
        pub_spend_key_obj = AddrUtils.ValidateAndGetEd25519MoneroKey(pub_skey)
        pub_view_key_obj = AddrUtils.ValidateAndGetEd25519MoneroKey(pub_vkey)

        data = net_ver + pub_spend_key_obj.RawCompressed().ToBytes() + pub_view_key_obj.RawCompressed().ToBytes() + payment_id
        checksum = CryptoUtils.Kekkak256(data)

        return Base58XmrEncoder.Encode(data + checksum[:XmrAddrConst.CHECKSUM_BYTE_LEN])


class XmrAddr(IAddrEncoder):
    """ Monero address class. It allows the Monero address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get address in Monero format.

        Args:
            pub_key (bytes or IPublicKey): Public spend key bytes or object

        Other Parameters:
            pub_vkey (bytes or IPublicKey): Public view key bytes or object
            net_ver (bytes)               : Net version
            payment_id (bytes, optional)  : Payment ID (only for integrated addresses)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519-monero
        """
        pub_vkey = kwargs["pub_vkey"]
        net_ver = kwargs["net_ver"]

        return XmrAddrUtils.EncodeKeyGeneric(pub_key, pub_vkey, net_ver)


class XmrIntegratedAddr(IAddrEncoder):
    """ Monero address class. It allows the Monero address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get Monero integrated address.

        Args:
            pub_key (bytes or IPublicKey): Public spend key bytes or object

        Other Parameters:
            pub_vkey (bytes or IPublicKey): Public view key bytes or object
            payment_id (bytes)            : Payment ID

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519-monero
        """
        pub_vkey = kwargs["pub_vkey"]
        payment_id = kwargs["payment_id"]

        return XmrAddrUtils.EncodeKeyGeneric(pub_key, pub_vkey, MoneroConf.ADDR_NET_VER_INT, payment_id)
