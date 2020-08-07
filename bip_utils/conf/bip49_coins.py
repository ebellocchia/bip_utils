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
from bip_utils.addr               import P2SH, BchP2SH
from bip_utils.conf.bip_coin_base import BipCoinBase
from bip_utils.conf.bip_coin_conf import *


class Bip49Coin(BipCoinBase):
    """ Generic class for BIP-049 coins. """

    def __init__(self, coin_conf, is_testnet, addr_fct):
        """ Construct class.

        Args:
            coin_conf (class): Coin configuration class
            is_testnet (bool): True if test net, false otherwise
            addr_fct (class) : Address class
        """
        super().__init__(coin_conf, coin_conf.BIP49_KEY_NET_VER, is_testnet, addr_fct)


class Bip49Litecoin(Bip49Coin):
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
            return self.m_key_net_ver.Main()["btc"] if not self.m_coin_conf.EX_KEY_ALT else self.m_key_net_ver.Main()["alt"]
        else:
            return self.m_key_net_ver.Test()

    def ComputeAddress(self, pub_key):
        """ Compute address from public key.
        Litecoin overrides the method because it can have 2 different address versions.

        Args:
            pub_key (BipPublicKey object): BipPublicKey object

        Returns:
            str: Address string
        """
        p2sh_ver = self.m_coin_conf.P2SH_NET_VER if not self.m_coin_conf.P2SH_DEPR_ADDR else self.m_coin_conf.P2SH_DEPR_NET_VER
        addr_ver = p2sh_ver.Main() if not self.m_is_testnet else p2sh_ver.Test()
        return self.m_addr_fct.ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)


class Bip49BitcoinCash(Bip49Coin):
    """ Bitcoin Cash BIP-0049 class.
    It overrides ComputeAddress to return different addresses depending on the configuration.
    """

    def ComputeAddress(self, pub_key):
        """ Compute address from public key.
        Bitcoin Cash overrides the method because it can have 2 different addresses types

        Args:
            pub_key (BipPublicKey object): BipPublicKey object

        Returns:
            str: Address string
        """
        if not self.m_coin_conf.LEGACY_ADDR:
            addr_ver = self.m_coin_conf.BCH_P2SH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.BCH_P2SH_NET_VER.Test()
            return self.m_addr_fct["bch"].ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver["hrp"], addr_ver["net_ver"])
        else:
            addr_ver = self.m_coin_conf.LEGACY_P2SH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.LEGACY_P2SH_NET_VER.Test()
            return self.m_addr_fct["legacy"].ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)


# Configuration for Bitcoin main net
Bip49BitcoinMainNet = Bip49Coin(coin_conf  = BitcoinConf,
                                is_testnet = False,
                                addr_fct   = P2SH)
# Configuration for Bitcoin test net
Bip49BitcoinTestNet = Bip49Coin(coin_conf  = BitcoinConf,
                                is_testnet = True,
                                addr_fct   = P2SH)

# Configuration for Bitcoin Cash main net
Bip49BitcoinCashMainNet = Bip49BitcoinCash(coin_conf  = BitcoinCashConf,
                                           is_testnet = False,
                                           addr_fct   = {"legacy" : P2SH, "bch" : BchP2SH})
# Configuration for Bitcoin Cash test net
Bip49BitcoinCashTestNet = Bip49BitcoinCash(coin_conf  = BitcoinCashConf,
                                           is_testnet = True,
                                           addr_fct   = {"legacy" : P2SH, "bch" : BchP2SH})

# Configuration for BitcoinSV main net
Bip49BitcoinSvMainNet = Bip49Coin(coin_conf  = BitcoinSvConf,
                                  is_testnet = False,
                                  addr_fct   = P2SH)
# Configuration for BitcoinSV test net
Bip49BitcoinSvTestNet = Bip49Coin(coin_conf  = BitcoinSvConf,
                                  is_testnet = True,
                                  addr_fct   = P2SH)

# Configuration for Litecoin main net
Bip49LitecoinMainNet = Bip49Litecoin(coin_conf  = LitecoinConf,
                                     is_testnet = False,
                                     addr_fct   = P2SH)
# Configuration for Litecoin test net
Bip49LitecoinTestNet = Bip49Litecoin(coin_conf  = LitecoinConf,
                                     is_testnet = True,
                                     addr_fct   = P2SH)

# Configuration for Dogecoin main net
Bip49DogecoinMainNet = Bip49Coin(coin_conf  = DogecoinConf,
                                 is_testnet = False,
                                 addr_fct   = P2SH)
# Configuration for Dogecoin test net
Bip49DogecoinTestNet = Bip49Coin(coin_conf  = DogecoinConf,
                                 is_testnet = True,
                                 addr_fct   = P2SH)

# Configuration for Dash main net
Bip49DashMainNet = Bip49Coin(coin_conf  = DashConf,
                             is_testnet = False,
                             addr_fct   = P2SH)
# Configuration for Dash test net
Bip49DashTestNet = Bip49Coin(coin_conf  = DashConf,
                             is_testnet = True,
                             addr_fct   = P2SH)

# Configuration for Zcash main net
Bip49ZcashMainNet = Bip49Coin(coin_conf  = ZcashConf,
                             is_testnet = False,
                             addr_fct   = P2SH)
# Configuration for Zcash test net
Bip49ZcashTestNet = Bip49Coin(coin_conf  = ZcashConf,
                             is_testnet = True,
                             addr_fct   = P2SH)
