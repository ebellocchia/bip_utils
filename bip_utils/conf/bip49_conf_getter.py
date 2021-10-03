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
from bip_utils.conf.bip_coin_conf import BipCoinConf
from bip_utils.conf.bip44_coins import Bip44Coins
from bip_utils.conf.bip49_coin_conf import *


class Bip49ConfGetterConst:
    """ Class container for Bip49 configuration getter constants. """

    # Map from Bip44Coins to configuration classes
    COIN_TO_CONF: Dict[Bip44Coins, BipCoinConf] = {
        Bip44Coins.BITCOIN: Bip49BitcoinMainNet,
        Bip44Coins.BITCOIN_TESTNET: Bip49BitcoinTestNet,
        Bip44Coins.BITCOIN_CASH: Bip49BitcoinCashMainNet,
        Bip44Coins.BITCOIN_CASH_TESTNET: Bip49BitcoinCashTestNet,
        Bip44Coins.BITCOIN_SV: Bip49BitcoinSvMainNet,
        Bip44Coins.BITCOIN_SV_TESTNET: Bip49BitcoinSvTestNet,
        Bip44Coins.DASH: Bip49DashMainNet,
        Bip44Coins.DASH_TESTNET: Bip49DashTestNet,
        Bip44Coins.DOGECOIN: Bip49DogecoinMainNet,
        Bip44Coins.DOGECOIN_TESTNET: Bip49DogecoinTestNet,
        Bip44Coins.LITECOIN: Bip49LitecoinMainNet,
        Bip44Coins.LITECOIN_TESTNET: Bip49LitecoinTestNet,
        Bip44Coins.ZCASH: Bip49ZcashMainNet,
        Bip44Coins.ZCASH_TESTNET: Bip49ZcashTestNet,
    }


class Bip49ConfGetter:
    """ Bip49 configuration getter class. It allows to get the Bip49 configuration of a specific coin. """

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
        return Bip49ConfGetterConst.COIN_TO_CONF[coin_type]
