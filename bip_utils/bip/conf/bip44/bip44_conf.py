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
from bip_utils.addr import *
from bip_utils.bip.bip32 import (
    Bip32Const, Bip32KeyNetVersions, Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip, Bip32Nist256p1, Bip32Secp256k1
)
from bip_utils.bip.conf.common import *
from bip_utils.coin_conf import *


# Bitcoin key net version for main net (same as BIP32)
_BIP44_BTC_KEY_NET_VER_MAIN: Bip32KeyNetVersions = Bip32Const.MAIN_NET_KEY_NET_VERSIONS
# Bitcoin key net version for test net (same as BIP32)
_BIP44_BTC_KEY_NET_VER_TEST: Bip32KeyNetVersions = Bip32Const.TEST_NET_KEY_NET_VERSIONS

# Configuration for Algorand
Bip44Algorand: BipCoinConf = BipCoinConf(
    coin_name=AlgorandConf.COIN_NAME,
    coin_idx=283,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=AlgoAddr,
    addr_params={},
)

# Configuration for Avax C-Chain
Bip44AvaxCChain: BipCoinConf = BipCoinConf(
    coin_name=AvaxCChainConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)
# Configuration for Avax P-Chain
Bip44AvaxPChain: BipCoinConf = BipCoinConf(
    coin_name=AvaxPChainConf.COIN_NAME,
    coin_idx=9000,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AvaxPChainAddr,
    addr_params={},
)
# Configuration for Avax X-Chain
Bip44AvaxXChain: BipCoinConf = BipCoinConf(
    coin_name=AvaxXChainConf.COIN_NAME,
    coin_idx=9000,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AvaxXChainAddr,
    addr_params={},
)

# Configuration for Band Protocol
Bip44BandProtocol: BipCoinConf = BipCoinConf(
    coin_name=BandProtocolConf.COIN_NAME,
    coin_idx=494,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": BandProtocolConf.ADDR_HRP},
)

# Configuration for Binance Chain
Bip44BinanceChain: BipCoinConf = BipCoinConf(
    coin_name=BinanceChainConf.COIN_NAME,
    coin_idx=714,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": BinanceChainConf.ADDR_HRP},
)
# Configuration for Binance Smart Chain
Bip44BinanceSmartChain: BipCoinConf = BipCoinConf(
    coin_name=BinanceSmartChainConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Bitcoin main net
Bip44BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_MN,
    coin_idx=0,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": BitcoinConf.P2PKH_NET_VER_MN},
)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": BitcoinConf.P2PKH_NET_VER_TN},
)

# Configuration for Bitcoin Cash main net
Bip44BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=BitcoinCashConf.COIN_NAME_MN,
    coin_idx=145,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinCashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=BchP2PKHAddr,
    addr_params={
        "std": {
            "net_ver": BitcoinCashConf.P2PKH_STD_NET_VER_MN,
            "hrp": BitcoinCashConf.P2PKH_STD_HRP_MN,
        },
        "legacy": {
            "net_ver":  BitcoinCashConf.P2PKH_LEGACY_NET_VER_MN,
        }
    },
    addr_cls_legacy=P2PKHAddr,
)
# Configuration for Bitcoin Cash test net
Bip44BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=BitcoinCashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinCashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=BchP2PKHAddr,
    addr_params={
        "std": {
            "net_ver": BitcoinCashConf.P2PKH_STD_NET_VER_TN,
            "hrp": BitcoinCashConf.P2PKH_STD_HRP_TN,
        },
        "legacy": {
            "net_ver": BitcoinCashConf.P2PKH_LEGACY_NET_VER_TN,
        }
    },
    addr_cls_legacy=P2PKHAddr,
)

# Configuration for BitcoinSV main net
Bip44BitcoinSvMainNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinSvConf.COIN_NAME_MN,
    coin_idx=236,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BitcoinSvConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": BitcoinSvConf.P2PKH_NET_VER_MN},
)
# Configuration for BitcoinSV test net
Bip44BitcoinSvTestNet: BipCoinConf = BipCoinConf(
    coin_name=BitcoinSvConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BitcoinSvConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": BitcoinSvConf.P2PKH_NET_VER_TN},
)

# Configuration for Cosmos
Bip44Cosmos: BipCoinConf = BipCoinConf(
    coin_name=CosmosConf.COIN_NAME,
    coin_idx=118,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": CosmosConf.ADDR_HRP},
)

# Configuration for Dash main net
Bip44DashMainNet: BipCoinConf = BipCoinConf(
    coin_name=DashConf.COIN_NAME_MN,
    coin_idx=5,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=DashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": DashConf.P2PKH_NET_VER_MN},
)
# Configuration for Dash test net
Bip44DashTestNet: BipCoinConf = BipCoinConf(
    coin_name=DashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=DashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": DashConf.P2PKH_NET_VER_TN},
)

# Configuration for Dogecoin main net
Bip44DogecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=DogecoinConf.COIN_NAME_MN,
    coin_idx=3,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x02\xfa\xca\xfd",
                                    b"\x02\xfa\xc3\x98"),   # dgub / dgpv
    wif_net_ver=DogecoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": DogecoinConf.P2PKH_NET_VER_MN},
)
# Configuration for Dogecoin test net
Bip44DogecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=DogecoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x32\xa9\xa8",
                                    b"\x04\x32\xa2\x43"),   # tgub / tgpv
    wif_net_ver=DogecoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": DogecoinConf.P2PKH_NET_VER_TN},
)

# Configuration for Elrond
Bip44Elrond: BipCoinConf = BipCoinConf(
    coin_name=ElrondConf.COIN_NAME,
    coin_idx=508,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=EgldAddr,
    addr_params={},
)

# Configuration for Eos
Bip44Eos: BipCoinConf = BipCoinConf(
    coin_name=EosConf.COIN_NAME,
    coin_idx=194,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EosAddr,
    addr_params={},
)

# Configuration for Ethereum
Bip44Ethereum: BipCoinConf = BipCoinConf(
    coin_name=EthereumConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)
# Configuration for Ethereum Classic
Bip44EthereumClassic: BipCoinConf = BipCoinConf(
    coin_name=EthereumClassicConf.COIN_NAME,
    coin_idx=61,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Fantom Opera
Bip44FantomOpera: BipCoinConf = BipCoinConf(
    coin_name=FantomOperaConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Filecoin
Bip44Filecoin: BipCoinConf = BipCoinConf(
    coin_name=FilecoinConf.COIN_NAME,
    coin_idx=461,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=FilSecp256k1Addr,
    addr_params={},
)

# Configuration for Harmony One (Metamask address)
Bip44HarmonyOneMetamask: BipCoinConf = BipCoinConf(
    coin_name=HarmonyOneConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)
# Configuration for Harmony One (Ethereum address)
Bip44HarmonyOneEth: BipCoinConf = BipCoinConf(
    coin_name=HarmonyOneConf.COIN_NAME,
    coin_idx=1023,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)
# Configuration for Harmony One (Atom address)
Bip44HarmonyOneAtom: BipCoinConf = BipCoinConf(
    coin_name=HarmonyOneConf.COIN_NAME,
    coin_idx=1023,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=OneAddr,
    addr_params={},
)

# Configuration for Huobi Chain
Bip44HuobiChain: BipCoinConf = BipCoinConf(
    coin_name=HuobiChainConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for IRISnet
Bip44IrisNet: BipCoinConf = BipCoinConf(
    coin_name=IrisNetConf.COIN_NAME,
    coin_idx=118,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": IrisNetConf.ADDR_HRP},
)

# Configuration for Kava
Bip44Kava: BipCoinConf = BipCoinConf(
    coin_name=KavaConf.COIN_NAME,
    coin_idx=494,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": KavaConf.ADDR_HRP},
)

# Configuration for Kusama (ed25519 SLIP-0010)
Bip44KusamaEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=KusamaConf.COIN_NAME,
    coin_idx=354,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=SubstrateEd25519Addr,
    addr_params={"ss58_format": KusamaConf.ADDR_SS58_FORMAT},
)

# Configuration for Litecoin main net
Bip44LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=LitecoinConf.COIN_NAME_MN,
    coin_idx=2,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    alt_key_net_ver=Bip32KeyNetVersions(b"\x01\x9d\xa4\x62",
                                        b"\x01\x9d\x9c\xfe"),   # Ltpv / Ltub
    wif_net_ver=LitecoinConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={
        "std_net_ver": LitecoinConf.P2PKH_STD_NET_VER_MN,
        "depr_net_ver": LitecoinConf.P2PKH_DEPR_NET_VER_MN,
    },
)
# Configuration for Litecoin test net
Bip44LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=LitecoinConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                    b"\x04\x36\xef\x7d"),       # ttub / ttpv
    alt_key_net_ver=Bip32KeyNetVersions(b"\x04\x36\xf6\xe1",
                                        b"\x04\x36\xef\x7d"),   # ttub / ttpv
    wif_net_ver=LitecoinConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={
        "std_net_ver": LitecoinConf.P2PKH_STD_NET_VER_TN,
        "depr_net_ver": LitecoinConf.P2PKH_DEPR_NET_VER_TN,
    },
)

# Configuration for Monero (ed25519 SLIP-0010)
Bip44MoneroEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=MoneroConf.COIN_NAME_MN,
    coin_idx=128,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=XmrAddr,
    addr_params={},
)

# Configuration for Monero (secp256k1)
Bip44MoneroSecp256k1: BipCoinConf = BipCoinConf(
    coin_name=MoneroConf.COIN_NAME_MN,
    coin_idx=128,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=XmrAddr,
    addr_params={},
)

# Configuration for Nano
Bip44Nano: BipCoinConf = BipCoinConf(
    coin_name=NanoConf.COIN_NAME,
    coin_idx=165,
    is_testnet=False,
    def_path="0'",
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Blake2bSlip,
    addr_cls=NanoAddr,
    addr_params={},
)

# Configuration for Neo
Bip44Neo: BipCoinConf = BipCoinConf(
    coin_name=NeoConf.COIN_NAME,
    coin_idx=888,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Nist256p1,
    addr_cls=NeoAddr,
    addr_params={"ver": NeoConf.ADDR_VER},
)

# Configuration for NG
Bip44NineChroniclesGold: BipCoinConf = BipCoinConf(
    coin_name=NineChroniclesGoldConf.COIN_NAME,
    coin_idx=567,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for OKEx Chain (Ethereum address)
Bip44OkexChainEth: BipCoinConf = BipCoinConf(
    coin_name=OkexChainConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for OKEx Chain (Atom address)
Bip44OkexChainAtom: BipCoinConf = BipCoinConf(
    coin_name=OkexChainConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=OkexAddr,
    addr_params={},
)

# Configuration for OKEx Chain (old Atom address)
Bip44OkexChainAtomOld: BipCoinConf = BipCoinConf(
    coin_name=OkexChainConf.COIN_NAME,
    coin_idx=996,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=OkexAddr,
    addr_params={},
)

# Configuration for Ontology
Bip44Ontology: BipCoinConf = BipCoinConf(
    coin_name=OntologyConf.COIN_NAME,
    coin_idx=1024,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Nist256p1,
    addr_cls=NeoAddr,
    addr_params={"ver": OntologyConf.ADDR_VER},
)

# Configuration for Polkadot (ed25519 SLIP-0010)
Bip44PolkadotEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=PolkadotConf.COIN_NAME,
    coin_idx=354,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=SubstrateEd25519Addr,
    addr_params={"ss58_format": PolkadotConf.ADDR_SS58_FORMAT},
)

# Configuration for Polygon
Bip44Polygon: BipCoinConf = BipCoinConf(
    coin_name=PolygonConf.COIN_NAME,
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Ripple
Bip44Ripple: BipCoinConf = BipCoinConf(
    coin_name=RippleConf.COIN_NAME,
    coin_idx=144,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=XrpAddr,
    addr_params={},
)

# Configuration for Solana
Bip44Solana: BipCoinConf = BipCoinConf(
    coin_name=SolanaConf.COIN_NAME,
    coin_idx=501,
    is_testnet=False,
    def_path="0'",
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=SolAddr,
    addr_params={},
)

# Configuration for Stellar
Bip44Stellar: BipCoinConf = BipCoinConf(
    coin_name=StellarConf.COIN_NAME,
    coin_idx=148,
    is_testnet=False,
    def_path="0'",
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=XlmAddr,
    addr_params={"addr_type": XlmAddrTypes.PUB_KEY},
)

# Configuration for Terra
Bip44Terra: BipCoinConf = BipCoinConf(
    coin_name=TerraConf.COIN_NAME,
    coin_idx=330,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=AtomAddr,
    addr_params={"hrp": TerraConf.ADDR_HRP},
)

# Configuration for Tezos
Bip44Tezos: BipCoinConf = BipCoinConf(
    coin_name=TezosConf.COIN_NAME,
    coin_idx=1729,
    is_testnet=False,
    def_path="0'/0'",
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_cls=XtzAddr,
    addr_params={"prefix": XtzAddrPrefixes.TZ1},
)

# Configuration for Theta
Bip44Theta: BipCoinConf = BipCoinConf(
    coin_name=ThetaConf.COIN_NAME,
    coin_idx=500,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Tron
Bip44Tron: BipCoinConf = BipCoinConf(
    coin_name=TronConf.COIN_NAME,
    coin_idx=195,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=TrxAddr,
    addr_params={},
)

# Configuration for VeChain
Bip44VeChain: BipCoinConf = BipCoinConf(
    coin_name=VeChainConf.COIN_NAME,
    coin_idx=818,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=EthAddr,
    addr_params={},
)

# Configuration for Zcash main net
Bip44ZcashMainNet: BipCoinConf = BipCoinConf(
    coin_name=ZcashConf.COIN_NAME_MN,
    coin_idx=133,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=ZcashConf.WIF_NET_VER_MN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": ZcashConf.P2PKH_NET_VER_MN},
)
# Configuration for Zcash test net
Bip44ZcashTestNet: BipCoinConf = BipCoinConf(
    coin_name=ZcashConf.COIN_NAME_TN,
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=ZcashConf.WIF_NET_VER_TN,
    bip32_cls=Bip32Secp256k1,
    addr_cls=P2PKHAddr,
    addr_params={"net_ver": ZcashConf.P2PKH_NET_VER_TN},
)

# Configuration for Zilliqa
Bip44Zilliqa: BipCoinConf = BipCoinConf(
    coin_name=ZilliqaConf.COIN_NAME,
    coin_idx=313,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=_BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_cls=ZilAddr,
    addr_params={},
)
