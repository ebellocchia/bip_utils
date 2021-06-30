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
from bip_utils.conf.bip_coin_conf_enum import AddrTypes, Bip32Types
from bip_utils.conf.bip_coin_conf_common import *
from bip_utils.conf.bip_coin_conf_helper import CoinNames, KeyNetVersions
from bip_utils.conf.bip_coin_conf import BipCoinConf, BipBitcoinCashConf, BipLitecoinConf


# Bitcoin key net version for main net (xpub / xprv)
BIP44_BTC_KEY_NET_VER_MAIN: KeyNetVersions = KeyNetVersions(b"0488b21e", b"0488ade4")
# Bitcoin key net version for test net (tpub / tprv)
BIP44_BTC_KEY_NET_VER_TEST: KeyNetVersions = KeyNetVersions(b"043587cf", b"04358394")
# Bitcoin P2PKH net version for main net
BIP44_BTC_P2PKH_NET_VER_MAIN: bytes = b"\x00"
# Bitcoin P2PKH net version for test net
BIP44_BTC_P2PKH_NET_VER_TEST: bytes = b"\x6f"

# Configuration for Algorand
Bip44Algorand: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Algorand", "ALGO"),
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={},
    addr_type=AddrTypes.ALGO)

# Configuration for Avax C-Chain
Bip44AvaxCChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax C-Chain", "AVAX"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Avax P-Chain
Bip44AvaxPChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax P-Chain", "AVAX"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "avax", "prefix": "P-"},
    addr_type=AddrTypes.AVAX_P)
# Configuration for Avax X-Chain
Bip44AvaxXChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Avax X-Chain", "AVAX"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "avax", "prefix": "X-"},
    addr_type=AddrTypes.AVAX_X)

# Configuration for Band Protocol
Bip44BandProtocol: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Band Protocol", "BAND"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "band"},
    addr_type=AddrTypes.ATOM)

# Configuration for Binance Chain
Bip44BinanceChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Binance Chain", "BNB"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "bnb"},
    addr_type=AddrTypes.ATOM)
# Configuration for Binance Smart Chain
Bip44BinanceSmartChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Binance Smart Chain", "BNB"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Bitcoin main net
Bip44BitcoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin", "BTC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for Bitcoin test net
Bip44BitcoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Bitcoin TestNet", "BTC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for Bitcoin Cash main net
Bip44BitcoinCashMainNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash", "BCH"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x00", "std_hrp": "bitcoincash", "legacy_net_ver":  BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH_BCH,
    addr_type_legacy=AddrTypes.P2PKH)
# Configuration for Bitcoin Cash test net
Bip44BitcoinCashTestNet: BipBitcoinCashConf = BipBitcoinCashConf(
    coin_name=CoinNames("Bitcoin Cash TestNet", "BCH"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x00", "std_hrp": "bchtest", "legacy_net_ver":  BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH_BCH,
    addr_type_legacy=AddrTypes.P2PKH)

# Configuration for BitcoinSV main net
Bip44BitcoinSvMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV", "BSV"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for BitcoinSV test net
Bip44BitcoinSvTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("BitcoinSV TestNet", "BSV"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for Cosmos
Bip44Cosmos: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Cosmos", "ATOM"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "cosmos"},
    addr_type=AddrTypes.ATOM)

# Configuration for Dash main net
Bip44DashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash", "DASH"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=b"\xcc",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x4c"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Dash test net
Bip44DashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dash TestNet", "DASH"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x8c"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Dogecoin main net
Bip44DogecoinMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin", "DOGE"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"02facafd", b"02fac398"),   # dgub / dgpv
    wif_net_ver=b"\x9e",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x1e"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Dogecoin test net
Bip44DogecoinTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Dogecoin TestNet", "DOGE"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"0432a9a8", b"0432a243"),   # tgub / tgpv
    wif_net_ver=b"\xf1",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x71"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Elrond
Bip44Elrond: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Elrond eGold", "eGLD"),
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={"hrp": "erd"},
    addr_type=AddrTypes.EGLD)

# Configuration for Ethereum
Bip44Ethereum: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ethereum", "ETH"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Ethereum Classic
Bip44EthereumClassic: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ethereum Classic", "ETC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Fantom Opera
Bip44FantomOpera: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Fantom Opera", "FTM"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Harmony One (Metamask address)
Bip44HarmonyOneMetamask: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Harmony One (Ethereum address)
Bip44HarmonyOneEth: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)
# Configuration for Harmony One (Atom address)
Bip44HarmonyOneAtom: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Harmony One", "ONE"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "one"},
    addr_type=AddrTypes.ONE)

# Configuration for Huobi Chain
Bip44HuobiChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Huobi Token", "HT"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for IRISnet
Bip44IrisNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("IRIS Network", "IRIS"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "iaa"},
    addr_type=AddrTypes.ATOM)

# Configuration for Kava
Bip44Kava: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Kava", "KAVA"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "kava"},
    addr_type=AddrTypes.ATOM)

# Configuration for Kusama (ed25519 SLIP-0010)
Bip44KusamaEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Kusama", "KSM"),
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={"ss58_ver": b"\x02"},
    addr_type=AddrTypes.SUBSTRATE)

# Configuration for Litecoin main net
Bip44LitecoinMainNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin", "LTC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    alt_key_net_ver=KeyNetVersions(b"019da462", b"019d9cfe"),   # Ltpv / Ltub
    wif_net_ver=b"\xb0",
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x30", "depr_net_ver": BIP44_BTC_P2PKH_NET_VER_MAIN},
    addr_type=AddrTypes.P2PKH)
# Configuration for Litecoin test net
Bip44LitecoinTestNet: BipLitecoinConf = BipLitecoinConf(
    coin_name=CoinNames("Litecoin TestNet", "LTC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=KeyNetVersions(b"0436f6e1", b"0436ef7d"),       # ttub / ttpv
    alt_key_net_ver=KeyNetVersions(b"0436f6e1", b"0436ef7d"),   # ttub / ttpv
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"std_net_ver": b"\x6f", "depr_net_ver": BIP44_BTC_P2PKH_NET_VER_TEST},
    addr_type=AddrTypes.P2PKH)

# Configuration for OKEx Chain (Ethereum address)
Bip44OkexChainEth: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("OKExChain", "OKT"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for OKEx Chain (Atom address)
Bip44OkexChainAtom: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("OKExChain", "OKT"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "ex"},
    addr_type=AddrTypes.OKEX)

# Configuration for Ontology
Bip44Ontology: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ontology", "ONT"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.NIST256P1,
    addr_conf={"ver": b"\x17"},
    addr_type=AddrTypes.NEO)

# Configuration for Neo
Bip44Neo: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("NEO", "NEO"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.NIST256P1,
    addr_conf={"ver": b"\x17"},
    addr_type=AddrTypes.NEO)

# Configuration for NG
Bip44NineChroniclesGold: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Nine Chronicles Gold", "NCG"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Polkadot (ed25519 SLIP-0010)
Bip44PolkadotEd25519Slip: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Polkadot", "DOT"),
    is_testnet=False,
    def_path=HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={"ss58_ver": b"\x00"},
    addr_type=AddrTypes.SUBSTRATE)

# Configuration for Polygon
Bip44Polygon: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Polygon", "MATIC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Ripple
Bip44Ripple: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Ripple", "XRP"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x00"},
    addr_type=AddrTypes.XRP)

# Configuration for Solana
Bip44Solana: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Solana", "SOL"),
    is_testnet=False,
    def_path="0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={},
    addr_type=AddrTypes.SOL)

# Configuration for Stellar
Bip44Stellar: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Stellar", "XLM"),
    is_testnet=False,
    def_path="0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={"ver": b"\x30"},
    addr_type=AddrTypes.XLM)

# Configuration for Terra
Bip44Terra: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Terra", "LUNA"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "terra"},
    addr_type=AddrTypes.ATOM)

# Configuration for Tezos
Bip44Tezos: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Tezos", "XTZ"),
    is_testnet=False,
    def_path="0'/0'",
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.ED25519_SLIP,
    addr_conf={"prefix": b"\x06\xa1\x9f"},
    addr_type=AddrTypes.XTZ)

# Configuration for Theta
Bip44Theta: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Theta Network", "THETA"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Tron
Bip44Tron: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Tron", "TRX"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"prefix": "41"},
    addr_type=AddrTypes.TRX)

# Configuration for VeChain
Bip44VeChain: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("VeChain", "VET"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={},
    addr_type=AddrTypes.ETH)

# Configuration for Zcash main net
Bip44ZcashMainNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash", "ZEC"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=BTC_WIF_NET_VER_MAIN,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x1c\xb8"},
    addr_type=AddrTypes.P2PKH)
# Configuration for Zcash test net
Bip44ZcashTestNet: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zcash TestNet", "ZEC"),
    is_testnet=True,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_TEST,
    wif_net_ver=BTC_WIF_NET_VER_TEST,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"net_ver": b"\x1d\x25"},
    addr_type=AddrTypes.P2PKH)

# Configuration for Zilliqa
Bip44Zilliqa: BipCoinConf = BipCoinConf(
    coin_name=CoinNames("Zilliqa", "ZIL"),
    is_testnet=False,
    def_path=NOT_HARDENED_DEF_PATH,
    key_net_ver=BIP44_BTC_KEY_NET_VER_MAIN,
    wif_net_ver=None,
    bip32_type=Bip32Types.SECP256K1,
    addr_conf={"hrp": "zil"},
    addr_type=AddrTypes.ZIL)
