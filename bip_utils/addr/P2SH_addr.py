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
import binascii
from typing import Union
from bip_utils.base58 import Base58Encoder
from bip_utils.bech32 import BchBech32Encoder
from bip_utils.conf import BitcoinConf
from bip_utils.ecc import EcdsaPublicKey, Secp256k1
from bip_utils.utils import CryptoUtils


class P2SHConst:
    """ Class container for P2SH constants. """

    # Script bytes
    SCRIPT_BYTES: bytes = b"0014"


class P2SHUtils:
    """ Class container for P2SH utility functions. """

    @staticmethod
    def AddScriptSig(pub_key: EcdsaPublicKey) -> bytes:
        """ Add script signature to public key and get address bytes.

        Args:
            pub_key (EcdsaPublicKey object) : Public key object

        Returns:
            bytes: Address bytes
        """
        # Key hash: Hash160(public_key)
        key_hash = CryptoUtils.Hash160(pub_key.RawCompressed().ToBytes())
        # Script signature: 0x0014 | Hash160(public_key)
        script_sig = binascii.unhexlify(P2SHConst.SCRIPT_BYTES) + key_hash
        # Address bytes = Hash160(script_signature)
        return CryptoUtils.Hash160(script_sig)


class P2SH:
    """ P2SH class. It allows the Pay-to-Script-Hash address generation. """

    @staticmethod
    def ToAddress(pub_key: Union[bytes, EcdsaPublicKey],
                  net_addr_ver: bytes = BitcoinConf.P2SH_NET_VER.Main()) -> str:
        """ Get address in P2SH format.

        Args:
            pub_key (bytes or EcdsaPublicKey): Public key bytes or object
            net_addr_ver (bytes, optional)   : Net address version, default is Bitcoin main network

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
        """
        if isinstance(pub_key, bytes):
            pub_key = Secp256k1.PublicKeyFromBytes(pub_key)

        # Final address: Base58Check(addr_prefix | address_bytes)
        return Base58Encoder.CheckEncode(net_addr_ver + P2SHUtils.AddScriptSig(pub_key))


class BchP2SH:
    """ Bitcoin Cash P2SH class. It allows the Bitcoin Cash P2SH generation. """

    @staticmethod
    def ToAddress(pub_key: Union[bytes, EcdsaPublicKey],
                  hrp: str,
                  net_addr_ver: bytes) -> str:
        """ Get address in Bitcoin Cash P2SH format.

        Args:
            pub_key (bytes or EcdsaPublicKey): Public key bytes or object
            hrp (str)                        : HRP
            net_addr_ver (bytes)             : Net address version

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
        """
        if isinstance(pub_key, bytes):
            pub_key = Secp256k1.PublicKeyFromBytes(pub_key)

        return BchBech32Encoder.Encode(hrp, net_addr_ver, P2SHUtils.AddScriptSig(pub_key))
