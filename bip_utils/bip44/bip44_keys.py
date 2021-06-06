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
from __future__ import annotations
from bip_utils.bip32 import Bip32KeyData, Bip32PublicKey, Bip32PrivateKey
from bip_utils.conf import BipCoinBase
from bip_utils.ecc import EllipticCurveTypes
from bip_utils.wif import WifEncoder


class Bip44PublicKey(Bip32PublicKey):
    """ BIP44 public key class.
    It extends Bip32PublicKey by adding the possibility to compute the address
    from the coin type.
    """

    def __init__(self,
                 key_bytes: bytes,
                 key_data: Bip32KeyData,
                 curve_type: EllipticCurveTypes,
                 coin_conf: BipCoinBase) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type
            coin_conf (BipCoinBase object) : BipCoinBase object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        super().__init__(key_bytes, key_data, curve_type)
        # Pre-compute address
        self.m_addr = coin_conf.ComputeAddress(self.m_pub_key)

    def ToAddress(self) -> str:
        """ Return address correspondent to the public key.

        Returns:
            str: Address
        """
        return self.m_addr


class Bip44PrivateKey(Bip32PrivateKey):
    """ BIP44 private key class.
    It extends Bip32PrivateKey by adding the possibility to compute the WIF
    from the coin type.
    """

    def __init__(self,
                 key_bytes: bytes,
                 key_data: Bip32KeyData,
                 curve_type: EllipticCurveTypes,
                 coin_conf: BipCoinBase) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes)              : Key bytes
            key_data (Bip32KeyData object) : Key data
            curve_type (EllipticCurveTypes): Elliptic curve type
            coin_conf (BipCoinBase object) : BipCoinBase object

        Raises:
            Bip32KeyError: If the key constructed from the bytes is not valid
        """
        super().__init__(key_bytes, key_data, curve_type)
        self.m_coin_conf = coin_conf

    def ToWif(self,
              compr_pub_key: bool = True) -> str:
        """ Return key in WIF format.

        Args:
            compr_pub_key (bool) : True if private key corresponds to a compressed public key, false otherwise

        Returns:
            str: Key in WIF format
        """
        wif_net_ver = self.m_coin_conf.WifNetVersion()

        return WifEncoder.Encode(self.Raw().ToBytes(), compr_pub_key, wif_net_ver) if wif_net_ver is not None else ""
