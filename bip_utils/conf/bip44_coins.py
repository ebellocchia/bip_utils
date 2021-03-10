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
from bip_utils.addr               import P2PKH, BchP2PKH, AtomAddr, EthAddr, TrxAddr, XrpAddr
from bip_utils.conf.bip_coin_base import BipCoinBase
from bip_utils.conf.bip_coin_conf import *


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
            return self.m_key_net_ver.Main()["btc"] if not self.m_coin_conf.EX_KEY_ALT else self.m_key_net_ver.Main()["alt"]
        else:
            return self.m_key_net_ver.Test()


class Bip44BitcoinCash(Bip44Coin):
    """ Bitcoin Cash BIP-0044 class.
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
            addr_ver = self.m_coin_conf.BCH_P2PKH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.BCH_P2PKH_NET_VER.Test()
            return self.m_addr_fct["bch"].ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver["hrp"], addr_ver["net_ver"])
        else:
            addr_ver = self.m_coin_conf.LEGACY_P2PKH_NET_VER.Main() if not self.m_is_testnet else self.m_coin_conf.LEGACY_P2PKH_NET_VER.Test()
            return self.m_addr_fct["legacy"].ToAddress(pub_key.RawCompressed().ToBytes(), addr_ver)


# Configuration for Bitcoin main net
Bip44BitcoinMainNet = Bip44Coin(coin_conf  = BitcoinConf,
                                is_testnet = False,
                                addr_fct   = P2PKH)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet = Bip44Coin(coin_conf  = BitcoinConf,
                                is_testnet = True,
                                addr_fct   = P2PKH)

# Configuration for Bitcoin Cash main net
Bip44BitcoinCashMainNet = Bip44BitcoinCash(coin_conf  = BitcoinCashConf,
                                           is_testnet = False,
                                           addr_fct   = {"legacy" : P2PKH, "bch" : BchP2PKH})
# Configuration for Bitcoin Cash test net
Bip44BitcoinCashTestNet = Bip44BitcoinCash(coin_conf  = BitcoinCashConf,
                                           is_testnet = True,
                                           addr_fct   = {"legacy" : P2PKH, "bch" : BchP2PKH})

# Configuration for BitcoinSV main net
Bip44BitcoinSvMainNet = Bip44Coin(coin_conf  = BitcoinSvConf,
                                  is_testnet = False,
                                  addr_fct   = P2PKH)
# Configuration for BitcoinSV test net
Bip44BitcoinSvTestNet = Bip44Coin(coin_conf  = BitcoinSvConf,
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

# Configuration for Zcash main net
Bip44ZcashMainNet = Bip44Coin(coin_conf  = ZcashConf,
                              is_testnet = False,
                              addr_fct   = P2PKH)
# Configuration for Zcash test net
Bip44ZcashTestNet = Bip44Coin(coin_conf  = ZcashConf,
                              is_testnet = True,
                              addr_fct   = P2PKH)

# Configuration for Ethereum
Bip44Ethereum = Bip44Coin(coin_conf  = EthereumConf,
                          is_testnet = False,
                          addr_fct   = EthAddr)
# Configuration for Ethereum Classic
Bip44EthereumClassic = Bip44Coin(coin_conf  = EthereumClassicConf,
                                 is_testnet = False,
                                 addr_fct   = EthAddr)

# Configuration for Ripple
Bip44Ripple = Bip44Coin(coin_conf  = RippleConf,
                        is_testnet = False,
                        addr_fct   = XrpAddr)

# Configuration for Tron
Bip44Tron = Bip44Coin(coin_conf  = TronConf,
                      is_testnet = False,
                      addr_fct   = TrxAddr)

# Configuration for VeChain
Bip44VeChain = Bip44Coin(coin_conf  = VeChainConf,
                         is_testnet = False,
                         addr_fct   = EthAddr)

# Configuration for Cosmos
Bip44Cosmos = Bip44Coin(coin_conf  = CosmosConf,
                        is_testnet = False,
                        addr_fct   = AtomAddr)

# Configuration for Band Protocol
Bip44BandProtocol = Bip44Coin(coin_conf  = BandProtocolConf,
                              is_testnet = False,
                              addr_fct   = AtomAddr)

# Configuration for Kava
Bip44Kava = Bip44Coin(coin_conf  = KavaConf,
                      is_testnet = False,
                      addr_fct   = AtomAddr)

# Configuration for IRISnet
Bip44IrisNet = Bip44Coin(coin_conf  = IrisNetConf,
                         is_testnet = False,
                         addr_fct   = AtomAddr)

# Configuration for Binance Chain
Bip44BinanceChain = Bip44Coin(coin_conf  = BinanceChainConf,
                              is_testnet = False,
                              addr_fct   = AtomAddr)
# Configuration for Binance Smart Chain
Bip44BinanceSmartChain = Bip44Coin(coin_conf  = BinanceSmartChainConf,
                                   is_testnet = False,
                                   addr_fct   = EthAddr)

# Configuration for NG
Bip44NineChroniclesGold = Bip44Coin(coin_conf  = NineChroniclesGoldConf,
                                    is_testnet = False,
                                    addr_fct   = EthAddr)
