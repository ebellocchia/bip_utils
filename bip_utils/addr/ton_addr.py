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

"""Module for Tron address encoding following the rest of the modules."""

# Imports
from typing import Any, Union

from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_encoder import IAddrEncoder

from bip_utils.ecc import IPublicKey

from bip_utils.ton.address.ton_address_encoder import TonAddressEncoder
from bip_utils.utils.misc import BytesUtils
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519KeysConst


class TonAddrEncoder(IAddrEncoder):
    """
    Ton address encoder class.
    It allows the Ton address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Ton address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs                     : Not used

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519, version is not valid or is_bounceable is not a boolean
        """
        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)
        pub_key_bytes = pub_key_obj.RawCompressed().ToBytes()
        # Remove the 0x00 prefix if present
        if (len(pub_key_bytes) == Ed25519KeysConst.PUB_KEY_BYTE_LEN + len(Ed25519KeysConst.PUB_KEY_PREFIX)
                and pub_key_bytes[0] == BytesUtils.ToInteger(Ed25519KeysConst.PUB_KEY_PREFIX)):
            pub_key_bytes = pub_key_bytes[1:]

        # Get and check address version. Default is v4, which is what is current employed in trust and ledger. 
        version = kwargs.get("version", "v4")

        # Version check is done in TonAddressEncoder, which will raise a ValueError if the version is not valid. We can skip it here to avoid code duplication.
        is_bounceable = kwargs.get("is_bounceable", False)
        if not isinstance(is_bounceable, bool):
            raise TypeError("is_bounceable must be a boolean")
        # Add prefix and encode
        return TonAddressEncoder( pub_key_bytes, version=version, is_bounceable=is_bounceable).encode()


# Deprecated: only for compatibility, Encoder class shall be used instead
TonAddr = TonAddrEncoder
