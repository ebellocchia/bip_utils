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

"""Module for getting Monero coins configuration."""

# Imports
from typing import Dict

from bip_utils.monero.conf.monero_coin_conf import MoneroCoinConf
from bip_utils.monero.conf.monero_coins import MoneroCoins
from bip_utils.monero.conf.monero_conf import MoneroConf


class MoneroConfGetterConst:
    """Class container for Monero configuration getter constants."""

    # Map from MoneroCoins to configuration classes
    COIN_TO_CONF: Dict[MoneroCoins, MoneroCoinConf] = {
        MoneroCoins.MONERO_MAINNET: MoneroConf.MainNet,
        MoneroCoins.MONERO_STAGENET: MoneroConf.StageNet,
        MoneroCoins.MONERO_TESTNET: MoneroConf.TestNet,
    }


class MoneroConfGetter:
    """
    Monero configuration getter class.
    It allows to get the Monero configuration of a specific coin.
    """

    @staticmethod
    def GetConfig(coin_type: MoneroCoins) -> MoneroCoinConf:
        """
        Get coin configuration.

        Args:
            coin_type (MoneroCoins): Coin type

        Returns:
            MoneroCoinConf: Coin configuration

        Raises:
            TypeError: If coin type is not of a MoneroCoins enumerative
        """
        if not isinstance(coin_type, MoneroCoins):
            raise TypeError("Coin type is not an enumerative of MoneroCoins")
        return MoneroConfGetterConst.COIN_TO_CONF[coin_type]
