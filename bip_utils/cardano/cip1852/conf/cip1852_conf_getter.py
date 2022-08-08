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

"""Module for getting CIP-1852 coins configuration."""

# Imports
from typing import Dict

from bip_utils.bip.conf.common import BipCoinConf, BipCoins
from bip_utils.cardano.cip1852.conf.cip1852_coins import Cip1852Coins
from bip_utils.cardano.cip1852.conf.cip1852_conf import Cip1852Conf


class Cip1852ConfGetterConst:
    """Class container for CIP-1852 configuration getter constants."""

    # Map from Cip1852Coins to configuration classes
    COIN_TO_CONF: Dict[BipCoins, BipCoinConf] = {
        Cip1852Coins.CARDANO_ICARUS: Cip1852Conf.CardanoIcarusMainNet,
        Cip1852Coins.CARDANO_LEDGER: Cip1852Conf.CardanoLedgerMainNet,
        Cip1852Coins.CARDANO_ICARUS_TESTNET: Cip1852Conf.CardanoIcarusTestNet,
        Cip1852Coins.CARDANO_LEDGER_TESTNET: Cip1852Conf.CardanoLedgerTestNet,
    }


class Cip1852ConfGetter:
    """
    CIP-1852 configuration getter class.
    It allows to get the CIP-1852 configuration of a specific coin.
    """

    @staticmethod
    def GetConfig(coin_type: BipCoins) -> BipCoinConf:
        """
        Get coin configuration.

        Args:
            coin_type (BipCoins): Coin type

        Returns:
            BipCoinConf: Coin configuration

        Raises:
            TypeError: If coin type is not of a Cip1852Coins enumerative
        """
        if not isinstance(coin_type, Cip1852Coins):
            raise TypeError("Coin type is not an enumerative of Cip1852Coins")
        return Cip1852ConfGetterConst.COIN_TO_CONF[coin_type]
