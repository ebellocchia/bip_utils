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
from bip_utils.base58 import Base58Encoder
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils


class EosAddrConst:
    """ Class container for EOS address constants. """

    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 4
    # Address prefix
    PREFIX: str = "EOS"


class EosAddr(IAddrEncoder):
    """ EOS address class. It allows the EOS address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get address in EOS format.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs: Not used

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        pub_key_obj = AddrUtils.ValidateAndGetSecp256k1Key(pub_key)
        pub_key_bytes = pub_key_obj.RawCompressed().ToBytes()

        checksum = CryptoUtils.Ripemd160(pub_key_bytes)[:EosAddrConst.CHECKSUM_BYTE_LEN]

        return EosAddrConst.PREFIX + Base58Encoder.Encode(pub_key_bytes + checksum)
