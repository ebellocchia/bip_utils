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
from bip_utils.ecc import Ed25519PublicKey
from bip_utils.utils import AlgoUtils, Base32, CryptoUtils


class AlgoAddrConst:
    """ Class container for Algorand address constants. """

    # Checksum length
    CHECKSUM_LEN: int = 4


class AlgoAddr:
    """ Algorand address class. It allows the Algorand address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, Ed25519PublicKey]) -> str:
        """ Get address in Algorand format.

        Args:
            pub_key (bytes or Ed25519PublicKey): Public key bytes or object

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        pub_key = AddrUtils.ValidateAndGetEd25519Key(pub_key)
        pub_key_bytes = pub_key.RawCompressed().ToBytes()[1:]

        # Compute checksum
        checksum = CryptoUtils.Sha512_256(pub_key_bytes)[-1 * AlgoAddrConst.CHECKSUM_LEN:]
        # Encode to Base32
        return AlgoUtils.Decode(Base32.Encode(pub_key_bytes + checksum)).strip("=")
