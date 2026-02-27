# Copyright (c) 2026 Emanuele Bellocchia
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

"""Module for TON address encoding."""

# Imports
from typing import Any, Union

from typing_extensions import override

from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.ecc import IPublicKey
from bip_utils.ton.addr import (
    TonAddrVersions,
    TonV3R1AddrEncoder,
    TonV3R2AddrEncoder,
    TonV4AddrEncoder,
    TonV5R1AddrEncoder,
)
from bip_utils.ton.ton_keys import TonPublicKey


class TonAddrEncoder(IAddrEncoder):
    """
    Ton address encoder class.
    It allows the Ton address encoding.
    """

    @override
    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Ton address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            version (TonAddrVersions, optional): Address version (default: v4)
            is_bounceable (bool, optional)     : Whether the address is bounceable (default: False)

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        version = kwargs.get("version", TonAddrVersions.V4)
        if not isinstance(version, TonAddrVersions):
            raise TypeError("Version is not an enumerative of TonAddrVersions")
        is_bounceable = kwargs.get("is_bounceable", False)

        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)
        ton_pub_key_obj = TonPublicKey.FromBytesOrKeyObject(pub_key_obj)

        if version == TonAddrVersions.V5R1:
            return TonV5R1AddrEncoder(ton_pub_key_obj).Encode(is_bounceable)
        elif version == TonAddrVersions.V4:
            return TonV4AddrEncoder(ton_pub_key_obj).Encode(is_bounceable)
        elif version == TonAddrVersions.V3R2:
            return TonV3R2AddrEncoder(ton_pub_key_obj).Encode(is_bounceable)
        else:
            return TonV3R1AddrEncoder(ton_pub_key_obj).Encode(is_bounceable)


# Deprecated: only for compatibility, Encoder class shall be used instead
TonAddr = TonAddrEncoder
