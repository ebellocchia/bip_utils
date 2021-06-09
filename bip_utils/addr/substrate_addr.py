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
from bip_utils.addr.utils import AddrUtils
from bip_utils.ecc import Ed25519PublicKey
from bip_utils.base58 import Base58Encoder
from bip_utils.utils import CryptoUtils


class SubstrateAddrConst:
    """ Class container for Substrate address constants. """

    # Checksum length
    CHECKSUM_LEN: int = 2
    # Prefix
    PREFIX: bytes = b"SS58PRE"


class SubstrateAddr:
    """ Substrate address class. It allows the Substrate address generation (SS58 encoding). """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, Ed25519PublicKey],
                  version: bytes) -> str:
        """ Get address in Substrate format.

        Args:
            pub_key (bytes or public key object): Public key bytes or object
            version (bytes): Version byte

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
        """
        pub_key_obj = AddrUtils.ValidateAndGetEd25519Key(pub_key)

        # Add version
        payload = version + pub_key_obj.RawCompressed().ToBytes()[1:]
        # Compute checksum
        checksum = CryptoUtils.Blake2b(SubstrateAddrConst.PREFIX + payload)[:SubstrateAddrConst.CHECKSUM_LEN]
        # Encode
        return Base58Encoder.Encode(payload + checksum)
