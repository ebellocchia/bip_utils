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
from bip_utils.base58 import Base58Encoder, Base58Alphabets
from bip_utils.bech32 import BchBech32Encoder
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import CryptoUtils


class P2PKHAddr(IAddrEncoder):
    """ P2PKH class. It allows the Pay-to-Public-Key-Hash address generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get address in P2PKH format.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            net_ver (bytes)                        : Net address version
            base58_alph (Base58Alphabets, optional): Base58 alphabet, Bitcoin alphabet by default

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        net_ver = kwargs["net_ver"]
        base58_alph = kwargs.get("base58_alph", Base58Alphabets.BITCOIN)

        pub_key_obj = AddrUtils.ValidateAndGetSecp256k1Key(pub_key)

        return Base58Encoder.CheckEncode(net_ver + CryptoUtils.Hash160(pub_key_obj.RawCompressed().ToBytes()),
                                         base58_alph)


class BchP2PKHAddr(IAddrEncoder):
    """ Bitcoin Cash P2PKH class. It allows the Bitcoin Cash P2PKH generation. """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """ Get address in Bitcoin Cash P2PKH format.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            hrp (str)      : HRP
            net_ver (bytes): Net address version

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        hrp = kwargs["hrp"]
        net_ver = kwargs["net_ver"]

        pub_key_obj = AddrUtils.ValidateAndGetSecp256k1Key(pub_key)

        return BchBech32Encoder.Encode(hrp,
                                       net_ver,
                                       CryptoUtils.Hash160(pub_key_obj.RawCompressed().ToBytes()))
