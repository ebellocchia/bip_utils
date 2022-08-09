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

"""Module with BIP38 utility functions."""

# Imports
from typing import Union

from bip_utils.addr import P2PKHAddr
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.crypto import DoubleSha256
from bip_utils.wif import WifPubKeyModes


# Alias for WifPubKeyModes
Bip38PubKeyModes = WifPubKeyModes


class Bip38AddrConst:
    """Class container for BIP38 address constants."""

    # Address hash length
    ADDR_HASH_LEN: int = 4


class Bip38Addr:
    """Class for BIP38 address computation."""

    @staticmethod
    def AddressHash(pub_key: Union[bytes, IPublicKey],
                    pub_key_mode: Bip38PubKeyModes) -> bytes:
        """
        Compute the address hash as specified in BIP38.

        Args:
            pub_key (bytes or IPublicKey)  : Public key bytes or object
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            bytes: Address hash

        Raises:
            TypeError: If the public key is not a Secp256k1PublicKey
            ValueError: If the public key bytes are not valid
        """

        # Compute the Bitcoin address
        address = P2PKHAddr.EncodeKey(pub_key,
                                      net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
                                      pub_key_mode=pub_key_mode)
        # Take the first four bytes of SHA256(SHA256())
        return DoubleSha256.QuickDigest(address)[:Bip38AddrConst.ADDR_HASH_LEN]
