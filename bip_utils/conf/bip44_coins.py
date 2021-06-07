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
from bip_utils.addr import (
    P2PKH, BchP2PKH, AlgoAddr, AtomAddr, AvaxPChainAddr, AvaxXChainAddr, EgldAddr, EthAddr,
    OkexAddr, NeoAddr, OneAddr, SolAddr, TrxAddr, XlmAddr, XrpAddr, XtzAddr
)
from bip_utils.bip32 import Bip32Base, Bip32Ed25519Slip, Bip32Nist256p1, Bip32Secp256k1
from bip_utils.conf.bip_coin_base import BipCoinBase
from bip_utils.conf.bip_coin_conf import *
from bip_utils.ecc import IPublicKey


class Bip44Coin(BipCoinBase):
    """ Generic class for BIP-044 coins. """

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
        super().__init__(coin_conf, coin_conf.BIP44_KEY_NET_VER, is_testnet, bip32_cls, addr_cls)


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
            return (self.m_key_net_ver.Main()["btc"]
                    if not self.m_coin_conf.EX_KEY_ALT
                    else self.m_key_net_ver.Main()["alt"])
        else:
            return self.m_key_net_ver.Test()


class Bip44BitcoinCash(Bip44Coin):
    """ Bitcoin Cash BIP-0044 class.
    It overrides EncodeKey to return different addresses depending on the configuration.
    """

    def EncodeKey(self,
                  pub_key: IPublicKey):
        """ Compute address from public key.
        Bitcoin Cash overrides the method because it can have 2 different addresses types

        Args:
            pub_key (IPublicKey object): IPublicKey object

        Returns:
            str: Address string
        """
        if not self.m_coin_conf.LEGACY_ADDR:
            addr_ver = (self.m_coin_conf.BCH_P2PKH_NET_VER.Main()
                        if not self.m_is_testnet
                        else self.m_coin_conf.BCH_P2PKH_NET_VER.Test())
            return self.m_addr_cls["bch"].EncodeKey(pub_key, addr_ver["hrp"], addr_ver["net_ver"])
        else:
            addr_ver = (self.m_coin_conf.LEGACY_P2PKH_NET_VER.Main()
                        if not self.m_is_testnet
                        else self.m_coin_conf.LEGACY_P2PKH_NET_VER.Test())
            return self.m_addr_cls["legacy"].EncodeKey(pub_key, addr_ver)


# Configuration for Bitcoin main net
Bip44BitcoinMainNet: Bip44Coin = Bip44Coin(
    coin_conf=BitcoinConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet: Bip44Coin = Bip44Coin(
    coin_conf=BitcoinConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Bitcoin Cash main net
Bip44BitcoinCashMainNet: Bip44BitcoinCash = Bip44BitcoinCash(
    coin_conf=BitcoinCashConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls={"legacy": P2PKH, "bch": BchP2PKH})
# Configuration for Bitcoin Cash test net
Bip44BitcoinCashTestNet: Bip44BitcoinCash = Bip44BitcoinCash(
    coin_conf=BitcoinCashConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls={"legacy": P2PKH, "bch": BchP2PKH})

# Configuration for BitcoinSV main net
Bip44BitcoinSvMainNet: Bip44Coin = Bip44Coin(
    coin_conf=BitcoinSvConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for BitcoinSV test net
Bip44BitcoinSvTestNet: Bip44Coin = Bip44Coin(
    coin_conf=BitcoinSvConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Litecoin main net
Bip44LitecoinMainNet: Bip44Litecoin = Bip44Litecoin(
    coin_conf=LitecoinConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for Litecoin test net
Bip44LitecoinTestNet: Bip44Litecoin = Bip44Litecoin(
    coin_conf=LitecoinConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Dogecoin main net
Bip44DogecoinMainNet: Bip44Coin = Bip44Coin(
    coin_conf=DogecoinConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for Dogecoin test net
Bip44DogecoinTestNet: Bip44Coin = Bip44Coin(
    coin_conf=DogecoinConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Dash main net
Bip44DashMainNet: Bip44Coin = Bip44Coin(
    coin_conf=DashConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for Dash test net
Bip44DashTestNet: Bip44Coin = Bip44Coin(
    coin_conf=DashConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Zcash main net
Bip44ZcashMainNet: Bip44Coin = Bip44Coin(
    coin_conf=ZcashConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)
# Configuration for Zcash test net
Bip44ZcashTestNet: Bip44Coin = Bip44Coin(
    coin_conf=ZcashConf,
    is_testnet=True,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKH)

# Configuration for Ethereum
Bip44Ethereum: Bip44Coin = Bip44Coin(
    coin_conf=EthereumConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)
# Configuration for Ethereum Classic
Bip44EthereumClassic: Bip44Coin = Bip44Coin(
    coin_conf=EthereumClassicConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Ripple
Bip44Ripple: Bip44Coin = Bip44Coin(
    coin_conf=RippleConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=XrpAddr)

# Configuration for Tron
Bip44Tron: Bip44Coin = Bip44Coin(
    coin_conf=TronConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=TrxAddr)

# Configuration for VeChain
Bip44VeChain: Bip44Coin = Bip44Coin(
    coin_conf=VeChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Cosmos
Bip44Cosmos: Bip44Coin = Bip44Coin(
    coin_conf=CosmosConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)

# Configuration for Band Protocol
Bip44BandProtocol: Bip44Coin = Bip44Coin(
    coin_conf=BandProtocolConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)

# Configuration for Kava
Bip44Kava: Bip44Coin = Bip44Coin(
    coin_conf=KavaConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)

# Configuration for IRISnet
Bip44IrisNet: Bip44Coin = Bip44Coin(
    coin_conf=IrisNetConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)

# Configuration for Terra
Bip44Terra: Bip44Coin = Bip44Coin(
    coin_conf=TerraConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)

# Configuration for Binance Chain
Bip44BinanceChain: Bip44Coin = Bip44Coin(
    coin_conf=BinanceChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr)
# Configuration for Binance Smart Chain
Bip44BinanceSmartChain: Bip44Coin = Bip44Coin(
    coin_conf=BinanceSmartChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Avax C-Chain
Bip44AvaxCChain: Bip44Coin = Bip44Coin(
    coin_conf=AvaxCChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)
# Configuration for Avax X-Chain
Bip44AvaxXChain: Bip44Coin = Bip44Coin(
    coin_conf=AvaxXChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AvaxXChainAddr)
# Configuration for Avax P-Chain
Bip44AvaxPChain: Bip44Coin = Bip44Coin(
    coin_conf=AvaxPChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AvaxPChainAddr)

# Configuration for Polygon
Bip44Polygon: Bip44Coin = Bip44Coin(
    coin_conf=PolygonConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Fantom Opera
Bip44FantomOpera: Bip44Coin = Bip44Coin(
    coin_conf=FantomOperaConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Harmony One (Metamask address)
Bip44HarmonyOneMetamask: Bip44Coin = Bip44Coin(
    coin_conf=HarmonyOneConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)
# Configuration for Harmony One (Ethereum address)
Bip44HarmonyOneEth: Bip44Coin = Bip44Coin(
    coin_conf=HarmonyOneConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)
# Configuration for Harmony One (Atom address)
Bip44HarmonyOneAtom: Bip44Coin = Bip44Coin(
    coin_conf=HarmonyOneConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=OneAddr)

# Configuration for Huobi Chain
Bip44HuobiChain: Bip44Coin = Bip44Coin(
    coin_conf=HuobiChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for OKEx Chain (Ethereum address)
Bip44OkexChainEth: Bip44Coin = Bip44Coin(
    coin_conf=OkexChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for OKEx Chain (Atom address)
Bip44OkexChainAtom: Bip44Coin = Bip44Coin(
    coin_conf=OkexChainConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=OkexAddr)

# Configuration for Theta
Bip44Theta: Bip44Coin = Bip44Coin(
    coin_conf=ThetaConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)

# Configuration for Algorand
Bip44Algorand: Bip44Coin = Bip44Coin(
    coin_conf=AlgorandConf,
    is_testnet=False,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=AlgoAddr)

# Configuration for Solana
Bip44Solana: Bip44Coin = Bip44Coin(
    coin_conf=SolanaConf,
    is_testnet=False,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=SolAddr)

# Configuration for Tezos
Bip44Tezos: Bip44Coin = Bip44Coin(
    coin_conf=TezosConf,
    is_testnet=False,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=XtzAddr)

# Configuration for Elrond
Bip44Elrond: Bip44Coin = Bip44Coin(
    coin_conf=ElrondConf,
    is_testnet=False,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=EgldAddr)

# Configuration for Stellar
Bip44Stellar: Bip44Coin = Bip44Coin(
    coin_conf=StellarConf,
    is_testnet=False,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=XlmAddr)

# Configuration for Neo
Bip44Neo: Bip44Coin = Bip44Coin(
    coin_conf=NeoConf,
    is_testnet=False,
    bip32_cls=Bip32Nist256p1,
    addr_cls=NeoAddr)

# Configuration for Ontology
Bip44Ontology: Bip44Coin = Bip44Coin(
    coin_conf=OntologyConf,
    is_testnet=False,
    bip32_cls=Bip32Nist256p1,
    addr_cls=NeoAddr)

# Configuration for NG
Bip44NineChroniclesGold: Bip44Coin = Bip44Coin(
    coin_conf=NineChroniclesGoldConf,
    is_testnet=False,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr)
