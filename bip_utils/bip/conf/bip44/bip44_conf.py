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
from bip_utils.bip.bip32 import (
    Bip32KeyNetVersions, Bip32Ed25519Slip, Bip32Ed25519Blake2bSlip, Bip32Nist256p1, Bip32Secp256k1
)
from bip_utils.bip.conf.common import *
from bip_utils.utils import CoinNames


# Bitcoin key net version for main net (xpub / xprv)
BIP44_BTC_KEY_NET_VER_MAIN: Bip32KeyNetVersions = Bip32KeyNetVersions(b"0488b21e", b"0488ade4")
# Bitcoin key net version for test net (tpub / tprv)
BIP44_BTC_KEY_NET_VER_TEST: Bip32KeyNetVersions = Bip32KeyNetVersions(b"043587cf", b"04358394")
# Bitcoin P2PKH net version for main net
BIP44_BTC_P2PKH_NET_VER_MAIN: bytes = b"\x00"
# Bitcoin P2PKH net version for test net
BIP44_BTC_P2PKH_NET_VER_TEST: bytes = b"\x6f"

# Configuration for Algorand
Bip44Algorand: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Algorand", "ALGO"),
    coin_idx=283,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={},
    addr_type=AddrTypes.ALGO)

# Configuration for Avax C-Chain
Bip44AvaxCChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax C-Chain", "AVAX"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Avax P-Chain
Bip44AvaxPChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax P-Chain", "AVAX"),
    coin_idx=9000,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "avax", "prefix": "P-"},
    addr_type=AddrTypes.AVAX_P)
# Configuration for Avax X-Chain
Bip44AvaxXChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax X-Chain", "AVAX"),
    coin_idx=9000,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "avax", "prefix": "X-"},
    addr_type=AddrTypes.AVAX_X)

# Configuration for Band Protocol
Bip44BandProtocol: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Band Protocol", "BAND"),
    coin_idx=494,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "band"},
    addr_type=AddrTypes.ATOM)

# Configuration for Binance Chain
Bip44BinanceChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Binance Chain", "BNB"),
    coin_idx=714,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "bnb"},
    addr_type=AddrTypes.ATOM)
# Configuration for Binance Smart Chain
Bip44BinanceSmartChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Binance Smart Chain", "BNB"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Bitcoin main net
Bip44BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin", "BTC"),
    coin_idx=0,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin TestNet", "BTC"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for Bitcoin Cash main net
Bip44BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash", "BCH"),
    coin_idx=145,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"std_net_ver": b"\x00", "std_hrp": "bitcoincash", "legacy_net_ver":  BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH_BCH,
    addr_type_legacy=AddrTypes.P2PKH)
# Configuration for Bitcoin Cash test net
Bip44BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash TestNet", "BCH"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"std_net_ver": b"\x00", "std_hrp": "bchtest", "legacy_net_ver":  BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH_BCH,
    addr_type_legacy=AddrTypes.P2PKH)

# Configuration for BitcoinSV main net
Bip44BitcoinSvMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV", "BSV"),
    coin_idx=236,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for BitcoinSV test net
Bip44BitcoinSvTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV TestNet", "BSV"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for Cosmos
Bip44Cosmos: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Cosmos", "ATOM"),
    coin_idx=118,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "cosmos"},
    addr_type=AddrTypes.ATOM)

# Configuration for Dash main net
Bip44DashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash", "DASH"),
    coin_idx=5,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=b"\xcc",
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x4c"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Dash test net
Bip44DashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash TestNet", "DASH"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x8c"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Dogecoin main net
Bip44DogecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin", "DOGE"),
    coin_idx=3,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"02facafd", b"02fac398"),   # dgub / dgpv
    wif_net_ver=b"\x9e",
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x1e"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Dogecoin test net
Bip44DogecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin TestNet", "DOGE"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"0432a9a8", b"0432a243"),   # tgub / tgpv
    wif_net_ver=b"\xf1",
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x71"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Elrond
Bip44Elrond: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Elrond eGold", "eGLD"),
    coin_idx=508,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={"hrp": "erd"},
    addr_type=AddrTypes.EGLD)

# Configuration for Ethereum
Bip44Ethereum: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ethereum", "ETH"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Ethereum Classic
Bip44EthereumClassic: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ethereum Classic", "ETC"),
    coin_idx=61,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Fantom Opera
Bip44FantomOpera: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Fantom Opera", "FTM"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Filecoin
Bip44Filecoin: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Filecoin", "FIL"),
    coin_idx=461,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"prefix": "f", "type": "1"},
    addr_type=AddrTypes.FIL)

# Configuration for Harmony One (Metamask address)
Bip44HarmonyOneMetamask: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Harmony One (Ethereum address)
Bip44HarmonyOneEth: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    coin_idx=1023,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Harmony One (Atom address)
Bip44HarmonyOneAtom: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    coin_idx=1023,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "one"},
    addr_type=AddrTypes.ONE)

# Configuration for Huobi Chain
Bip44HuobiChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Huobi Token", "HT"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for IRISnet
Bip44IrisNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("IRIS Network", "IRIS"),
    coin_idx=118,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "iaa"},
    addr_type=AddrTypes.ATOM)

# Configuration for Kava
Bip44Kava: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Kava", "KAVA"),
    coin_idx=494,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "kava"},
    addr_type=AddrTypes.ATOM)

# Configuration for Kusama (ed25519 SLIP-0010)
Bip44KusamaEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Kusama", "KSM"),
    coin_idx=354,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={"ss58_format": 2},
    addr_type=AddrTypes.SUBSTRATE)

# Configuration for Litecoin main net
Bip44LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin", "LTC"),
    coin_idx=2,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    alt_key_net_ver=Bip32KeyNetVersions(b"019da462", b"019d9cfe"),   # Ltpv / Ltub
    wif_net_ver=b"\xb0",
    bip32_cls=Bip32Secp256k1,
    addr_conf={"std_net_ver": b"\x30", "depr_net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for Litecoin test net
Bip44LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin TestNet", "LTC"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=Bip32KeyNetVersions(b"0436f6e1", b"0436ef7d"),       # ttub / ttpv
    alt_key_net_ver=Bip32KeyNetVersions(b"0436f6e1", b"0436ef7d"),   # ttub / ttpv
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"std_net_ver": b"\x6f", "depr_net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for Monero (ed25519 SLIP-0010)
Bip44MoneroEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Monero", "XMR"),
    coin_idx=128,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={},
    addr_type=AddrTypes.XMR)

# Configuration for Monero (secp256k1)
Bip44MoneroSecp256k1: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Monero", "XMR"),
    coin_idx=128,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.XMR)

# Configuration for OKEx Chain (Ethereum address)
Bip44OkexChainEth: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("OKExChain", "OKT"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for OKEx Chain (Atom address)
Bip44OkexChainAtom: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("OKExChain", "OKT"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "ex"},
    addr_type=AddrTypes.OKEX)

# Configuration for OKEx Chain (old Atom address)
Bip44OkexChainAtomOld: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("OKExChain", "OKT"),
    coin_idx=996,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "ex"},
    addr_type=AddrTypes.OKEX)

# Configuration for Ontology
Bip44Ontology: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ontology", "ONT"),
    coin_idx=1024,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Nist256p1,
    addr_conf={"ver": b"\x17"},
    addr_type=AddrTypes.NEO)

# Configuration for Nano
Bip44Nano: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Nano", "NANO"),
    coin_idx=165,
    is_testnet=False,
    def_path="0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Blake2bSlip,
    addr_conf={"prefix": "nano_"},
    addr_type=AddrTypes.NANO)

# Configuration for Neo
Bip44Neo: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("NEO", "NEO"),
    coin_idx=888,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Nist256p1,
    addr_conf={"ver": b"\x17", "prefix": b"\x21", "suffix": b"\xac"},
    addr_type=AddrTypes.NEO)

# Configuration for NG
Bip44NineChroniclesGold: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Nine Chronicles Gold", "NCG"),
    coin_idx=567,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Polkadot (ed25519 SLIP-0010)
Bip44PolkadotEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Polkadot", "DOT"),
    coin_idx=354,
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={"ss58_format": 0},
    addr_type=AddrTypes.SUBSTRATE)

# Configuration for Polygon
Bip44Polygon: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Polygon", "MATIC"),
    coin_idx=60,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Ripple
Bip44Ripple: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ripple", "XRP"),
    coin_idx=144,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x00"},
    addr_type=AddrTypes.XRP)

# Configuration for Solana
Bip44Solana: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Solana", "SOL"),
    coin_idx=501,
    is_testnet=False,
    def_path="0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={},
    addr_type=AddrTypes.SOL)

# Configuration for Stellar
Bip44Stellar: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Stellar", "XLM"),
    coin_idx=148,
    is_testnet=False,
    def_path="0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={"ver": b"\x30"},
    addr_type=AddrTypes.XLM)

# Configuration for Terra
Bip44Terra: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Terra", "LUNA"),
    coin_idx=330,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "terra"},
    addr_type=AddrTypes.ATOM)

# Configuration for Tezos
Bip44Tezos: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Tezos", "XTZ"),
    coin_idx=1729,
    is_testnet=False,
    def_path="0'/0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Ed25519Slip,
    addr_conf={"prefix": b"\x06\xa1\x9f"},
    addr_type=AddrTypes.XTZ)

# Configuration for Theta
Bip44Theta: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Theta Network", "THETA"),
    coin_idx=500,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Tron
Bip44Tron: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Tron", "TRX"),
    coin_idx=195,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"prefix": "41"},
    addr_type=AddrTypes.TRX)

# Configuration for VeChain
Bip44VeChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("VeChain", "VET"),
    coin_idx=818,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Zcash main net
Bip44ZcashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash", "ZEC"),
    coin_idx=133,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x1c\xb8"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Zcash test net
Bip44ZcashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash TestNet", "ZEC"),
    coin_idx=1,
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"net_ver": b"\x1d\x25"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Zilliqa
Bip44Zilliqa: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zilliqa", "ZIL"),
    coin_idx=313,
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_cls=Bip32Secp256k1,
    addr_conf={"hrp": "zil"},
    addr_type=AddrTypes.ZIL)
