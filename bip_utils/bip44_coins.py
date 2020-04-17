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
from .bip_coin_base import BipCoinBase
from .bip_coin_conf import *
from .P2PKH         import P2PKH
from .eth_addr      import EthAddr
from .xrp_addr      import XrpAddr


class Bip44Coin(BipCoinBase):
    """ Generic class for BIP-044 coins. """

    def __init__(self, coin_conf, is_testnet, addr_fct):
        """ Construct class.

        Args:
            coin_conf (class): Coin configuration class
            is_testnet (bool): True if test net, false otherwise
            addr_fct (class) : Address class
        """
        super().__init__(coin_conf, coin_conf.BIP44_KEY_NET_VER, is_testnet, addr_fct)


class Bip44Litecoin(Bip44Coin):
    """ Litecoin BIP-0044 class.
    It overrides KeyNetVersions to return different main net versions depending on the configuration.
    """

    def KeyNetVersions(self):
        """ Get key net versions. It overrides the method in BipCoinBase.
        Litecoin overrides the method because it can have 2 different main net versions.

        Returns:
            KeyNetVersions object: KeyNetVersions object
        """

        # Get standard or alternate version depending on the configuration flag
        if not self.m_is_testnet:
            return self.m_key_net_ver.Main()[0] if not self.m_coin_conf.EX_KEY_ALT else self.m_key_net_ver.Main()[1]
        else:
            return self.m_key_net_ver.Test()


# Configuration for Bitcoin main net
Bip44BitcoinMainNet = Bip44Coin(coin_conf  = BitcoinConf,
                                is_testnet = False,
                                addr_fct   = P2PKH)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet = Bip44Coin(coin_conf  = BitcoinConf,
                                is_testnet = True,
                                addr_fct   = P2PKH)
# Configuration for Litecoin main net
Bip44LitecoinMainNet = Bip44Litecoin(coin_conf  = LitecoinConf,
                                     is_testnet = False,
                                     addr_fct   = P2PKH)
# Configuration for Litecoin test net
Bip44LitecoinTestNet = Bip44Litecoin(coin_conf  = LitecoinConf,
                                    is_testnet = True,
                                    addr_fct   = P2PKH)
# Configuration for Dogecoin main net
Bip44DogecoinMainNet = Bip44Coin(coin_conf  = DogecoinConf,
                                 is_testnet = False,
                                 addr_fct   = P2PKH)
# Configuration for Dogecoin test net
Bip44DogecoinTestNet = Bip44Coin(coin_conf  = DogecoinConf,
                                 is_testnet = True,
                                 addr_fct   = P2PKH)
# Configuration for Dash main net
Bip44DashMainNet = Bip44Coin(coin_conf  = DashConf,
                             is_testnet = False,
                             addr_fct   = P2PKH)
# Configuration for Dash test net
Bip44DashTestNet = Bip44Coin(coin_conf  = DashConf,
                             is_testnet = True,
                             addr_fct   = P2PKH)
# Configuration for Ethereum main net
Bip44Ethereum = Bip44Coin(coin_conf  = EthereumConf,
                          is_testnet = False,
                          addr_fct   = EthAddr)
# Configuration for Ripple main net
Bip44Ripple = Bip44Coin(coin_conf  = RippleConf,
                        is_testnet = False,
                        addr_fct   = XrpAddr)
