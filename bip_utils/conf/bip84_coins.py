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
from typing import Type
from bip_utils.addr import P2WPKH
from bip_utils.bip32 import Bip32Base, Bip32Secp256k1
from bip_utils.conf.bip_coin_base import BipCoinBase
from bip_utils.conf.bip_coin_conf import *


class Bip84Coin(BipCoinBase):
    """ Generic class for BIP-084 coins. """

    def __init__(self,
                 coin_conf: Any,
                 is_testnet: bool,
                 bip32_cls: Type[Bip32Base],
                 addr_cls: Any) -> None:
        """ Construct class.

        Args:
            coin_conf (class)          : Coin configuration class
            is_testnet (bool)          : True if test net, false otherwise
            bip32_cls (Bip32Base class): Bip32 class
            addr_cls (class)           : Address class
        """
        super().__init__(coin_conf, coin_conf.BIP84_KEY_NET_VER, is_testnet, bip32_cls, addr_cls)


# Configuration for Bitcoin main net
Bip84BitcoinMainNet: Bip84Coin = Bip84Coin(
    coin_conf=BitcoinConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKH)
# Configuration for Bitcoin test net
Bip84BitcoinTestNet: Bip84Coin = Bip84Coin(
    coin_conf=BitcoinConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKH)

# Configuration for Litecoin main net
Bip84LitecoinMainNet: Bip84Coin = Bip84Coin(
    coin_conf=LitecoinConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKH)
# Configuration for Litecoin test net
Bip84LitecoinTestNet: Bip84Coin = Bip84Coin(
    coin_conf=LitecoinConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2WPKH)
