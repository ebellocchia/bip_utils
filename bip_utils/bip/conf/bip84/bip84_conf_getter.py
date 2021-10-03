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
from typing import Dict
from bip_utils.bip.conf.common import BipCoinConf
from bip_utils.bip.conf.bip44.bip44_coins import Bip44Coins
from bip_utils.bip.conf.bip84.bip84_conf import *


class Bip84ConfGetterConst:
    """ Class container for Bip84 configuration getter constants. """

    # Map from Bip44Coins to configuration classes
    COIN_TO_CONF: Dict[Bip44Coins, BipCoinConf] = {
        Bip44Coins.BITCOIN: Bip84BitcoinMainNet,
        Bip44Coins.BITCOIN_TESTNET: Bip84BitcoinTestNet,
        Bip44Coins.LITECOIN: Bip84LitecoinMainNet,
        Bip44Coins.LITECOIN_TESTNET: Bip84LitecoinTestNet,
    }


class Bip84ConfGetter:
    """ Bip84 configuration getter class. It allows to get the Bip84 configuration of a specific coin. """

    @staticmethod
    def GetConfig(coin_type: Bip44Coins) -> BipCoinConf:
        """ Get coin configuration.

        Args:
            coin_type (Bip44Coins): Coin type

        Returns:
            BipCoinConf: Coin configuration
        """
        if not isinstance(coin_type, Bip44Coins):
            raise TypeError("Coin type is not an enumerative of Bip44Coins")
        return Bip84ConfGetterConst.COIN_TO_CONF[coin_type]
