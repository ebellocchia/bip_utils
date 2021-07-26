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
from bip_utils.conf import Bip44Stellar
from bip_utils.ecc import IPublicKey
from bip_utils.utils import Base32Encoder, ConvUtils, CryptoUtils


class XlmAddr:
    """ Stellar address class. It allows the Stellar address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey]) -> str:
        """ Get address in Stellar format.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        pub_key_obj = AddrUtils.ValidateAndGetEd25519Key(pub_key)
        payload = Bip44Stellar.AddrConfKey("ver") + pub_key_obj.RawCompressed().ToBytes()[1:]

        # Compute checksum
        checksum = ConvUtils.ReverseBytes(CryptoUtils.XModemCrc(payload))
        # Encode to base32
        return Base32Encoder.EncodeNoPadding(payload + checksum)
