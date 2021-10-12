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

# Generic coins configuration

# Imports
from bip_utils.utils.conf import CoinNames


# Configuration for a Acala
class AcalaConf:
    COIN_NAME: CoinNames = CoinNames("Acala", "ACA")
    ADDR_SS58_FORMAT: int = 10


# Configuration for Algorand
class AlgorandConf:
    COIN_NAME: CoinNames = CoinNames("Algorand", "ALGO")


# Configuration for Avax C-Chain
class AvaxCChainConf:
    COIN_NAME: CoinNames = CoinNames("Avax C-Chain", "AVAX")


# Configuration for Avax P-Chain
class AvaxPChainConf:
    COIN_NAME: CoinNames = CoinNames("Avax P-Chain", "AVAX")
    ADDR_HRP: str = "avax"
    ADDR_PREFIX: str = "P-"


# Configuration for Avax X-Chain
class AvaxXChainConf:
    COIN_NAME: CoinNames = CoinNames("Avax X-Chain", "AVAX")
    ADDR_HRP: str = "avax"
    ADDR_PREFIX: str = "X-"


# Configuration for Band Protocol
class BandProtocolConf:
    COIN_NAME: CoinNames = CoinNames("Band Protocol", "BAND")
    ADDR_HRP: str = "band"


# Configuration for a Bifrost
class BifrostConf:
    COIN_NAME: CoinNames = CoinNames("Bifrost", "BNC")
    ADDR_SS58_FORMAT: int = 6


# Configuration for Binance Chain
class BinanceChainConf:
    COIN_NAME: CoinNames = CoinNames("Binance Chain", "BNB")
    ADDR_HRP: str = "bnb"


# Configuration for Binance Smart Chain
class BinanceSmartChainConf:
    COIN_NAME: CoinNames = CoinNames("Binance Smart Chain", "BNB")


# Configuration for Bitcoin
class BitcoinConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Bitcoin", "BTC")
    P2PKH_NET_VER_MN: bytes = b"\x00"
    P2SH_NET_VER_MN: bytes = b"\x05"
    P2WPKH_HRP_MN: str = "bc"
    P2WPKH_WIT_VER_MN: int = 0
    WIF_NET_VER_MN: bytes = b"\x80"
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Bitcoin TestNet", "BTC")
    P2PKH_NET_VER_TN: bytes = b"\x6f"
    P2SH_NET_VER_TN: bytes = b"\xc4"
    P2WPKH_HRP_TN: str = "tb"
    P2WPKH_WIT_VER_TN: int = 0
    WIF_NET_VER_TN: bytes = b"\xef"


# Configuration for Bitcoin Cash
class BitcoinCashConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Bitcoin Cash", "BCH")
    P2PKH_STD_HRP_MN: str = "bitcoincash"
    P2PKH_STD_NET_VER_MN: bytes = b"\x00"
    P2PKH_LEGACY_NET_VER_MN: bytes = BitcoinConf.P2PKH_NET_VER_MN
    P2SH_STD_HRP_MN: str = "bitcoincash"
    P2SH_STD_NET_VER_MN: bytes = b"\x08"
    P2SH_LEGACY_NET_VER_MN: bytes = BitcoinConf.P2SH_NET_VER_MN
    WIF_NET_VER_MN: bytes = BitcoinConf.WIF_NET_VER_MN
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Bitcoin Cash TestNet", "BCH")
    P2PKH_STD_HRP_TN: str = "bchtest"
    P2PKH_STD_NET_VER_TN: bytes = b"\x00"
    P2PKH_LEGACY_NET_VER_TN: bytes = BitcoinConf.P2PKH_NET_VER_TN
    P2SH_STD_HRP_TN: str = "bchtest"
    P2SH_STD_NET_VER_TN: bytes = b"\x08"
    P2SH_LEGACY_NET_VER_TN: bytes = BitcoinConf.P2SH_NET_VER_TN
    WIF_NET_VER_TN: bytes = BitcoinConf.WIF_NET_VER_TN


# Configuration for BitcoinSV
class BitcoinSvConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("BitcoinSV", "BSV")
    P2PKH_NET_VER_MN: bytes = BitcoinConf.P2PKH_NET_VER_MN
    P2SH_NET_VER_MN: bytes = BitcoinConf.P2SH_NET_VER_MN
    WIF_NET_VER_MN: bytes = BitcoinConf.WIF_NET_VER_MN
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("BitcoinSV TestNet", "BSV")
    P2PKH_NET_VER_TN: bytes = BitcoinConf.P2PKH_NET_VER_TN
    P2SH_NET_VER_TN: bytes = BitcoinConf.P2SH_NET_VER_TN
    WIF_NET_VER_TN: bytes = BitcoinConf.WIF_NET_VER_TN


# Configuration for a ChainX
class ChainXConf:
    COIN_NAME: CoinNames = CoinNames("ChainX", "PCX")
    ADDR_SS58_FORMAT: int = 44


# Configuration for Cosmos
class CosmosConf:
    COIN_NAME: CoinNames = CoinNames("Cosmos", "ATOM")
    ADDR_HRP: str = "cosmos"


# Configuration for Dash
class DashConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Dash", "DASH")
    P2PKH_NET_VER_MN: bytes = b"\x4c"
    P2SH_NET_VER_MN: bytes = b"\x10"
    WIF_NET_VER_MN: bytes = b"\xcc"
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Dash TestNet", "DASH")
    P2PKH_NET_VER_TN: bytes = b"\x8c"
    P2SH_NET_VER_TN: bytes = b"\x13"
    WIF_NET_VER_TN: bytes = BitcoinConf.WIF_NET_VER_TN


# Configuration for Dogecoin
class DogecoinConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Dogecoin", "DOGE")
    P2PKH_NET_VER_MN: bytes = b"\x1e"
    P2SH_NET_VER_MN: bytes = b"\x16"
    WIF_NET_VER_MN: bytes = b"\x9e"
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Dogecoin TestNet", "DOGE")
    P2PKH_NET_VER_TN: bytes = b"\x71"
    P2SH_NET_VER_TN: bytes = BitcoinConf.P2SH_NET_VER_TN
    WIF_NET_VER_TN: bytes = b"\xf1"


# Configuration for a Edgeware
class EdgewareConf:
    COIN_NAME: CoinNames = CoinNames("Edgeware", "EDG")
    ADDR_SS58_FORMAT: int = 7


# Configuration for Elrond
class ElrondConf:
    COIN_NAME: CoinNames = CoinNames("Elrond eGold", "eGLD")
    ADDR_HRP: str = "erd"


# Configuration for Eos
class EosConf:
    COIN_NAME: CoinNames = CoinNames("EOS", "EOS")
    ADDR_PREFIX: str = "EOS"


# Configuration for Ethereum
class EthereumConf:
    COIN_NAME: CoinNames = CoinNames("Ethereum", "ETH")
    ADDR_PREFIX: str = "0x"


# Configuration for Ethereum Classic
class EthereumClassicConf:
    COIN_NAME: CoinNames = CoinNames("Ethereum Classic", "ETC")


# Configuration for Fantom Opera
class FantomOperaConf:
    COIN_NAME: CoinNames = CoinNames("Fantom Opera", "FTM")


# Configuration for Filecoin
class FilecoinConf:
    COIN_NAME: CoinNames = CoinNames("Filecoin", "FIL")
    ADDR_PREFIX: str = "f"


# Configuration for a generic Substrate coin
class GenericSubstrateConf:
    COIN_NAME: CoinNames = CoinNames("Generic Substrate", "")
    ADDR_SS58_FORMAT: int = 42


# Configuration for Harmony One
class HarmonyOneConf:
    COIN_NAME: CoinNames = CoinNames("Harmony One", "ONE")
    ADDR_HRP: str = "one"


# Configuration for Huobi Chain
class HuobiChainConf:
    COIN_NAME: CoinNames = CoinNames("Huobi Token", "HT")


# Configuration for IRISnet
class IrisNetConf:
    COIN_NAME: CoinNames = CoinNames("IRIS Network", "IRIS")
    ADDR_HRP: str = "iaa"


# Configuration for Karura
class KaruraConf:
    COIN_NAME: CoinNames = CoinNames("Karura", "KAR")
    ADDR_SS58_FORMAT: int = 8


# Configuration for Kava
class KavaConf:
    COIN_NAME: CoinNames = CoinNames("Kava", "KAVA")
    ADDR_HRP: str = "kava"


# Configuration for Kusama
class KusamaConf:
    COIN_NAME: CoinNames = CoinNames("Kusama", "KSM")
    ADDR_SS58_FORMAT: int = 2


# Configuration for Litecoin
class LitecoinConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Litecoin", "LTC")
    P2PKH_STD_NET_VER_MN: bytes = b"\x30"
    P2PKH_DEPR_NET_VER_MN: bytes = BitcoinConf.P2PKH_NET_VER_MN
    P2SH_STD_NET_VER_MN: bytes = b"\x32"
    P2SH_DEPR_NET_VER_MN: bytes = BitcoinConf.P2SH_NET_VER_MN
    P2WPKH_HRP_MN: str = "ltc"
    P2WPKH_WIT_VER_MN: int = 0
    WIF_NET_VER_MN: bytes = b"\xb0"
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Litecoin TestNet", "LTC")
    P2PKH_STD_NET_VER_TN: bytes = b"\x6f"
    P2PKH_DEPR_NET_VER_TN: bytes = BitcoinConf.P2PKH_NET_VER_TN
    P2SH_STD_NET_VER_TN: bytes = b"\x3a"
    P2SH_DEPR_NET_VER_TN: bytes = BitcoinConf.P2SH_NET_VER_TN
    P2WPKH_HRP_TN: str = "tltc"
    P2WPKH_WIT_VER_TN: int = 0
    WIF_NET_VER_TN: bytes = BitcoinConf.WIF_NET_VER_TN


# Configuration for Monero
class MoneroConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Monero", "XMR")
    ADDR_NET_VER_MN: bytes = b"\x12"
    ADDR_INT_NET_VER_MN: bytes = b"\x13"
    SUBADDR_NET_VER_MN: bytes = b"\x2a"
    # Stage net
    COIN_NAME_SN: CoinNames = CoinNames("Monero StageNet", "XMR")
    ADDR_NET_VER_SN: bytes = b"\x18"
    ADDR_INT_NET_VER_SN: bytes = b"\x19"
    SUBADDR_NET_VER_SN: bytes = b"\x24"
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Monero TestNet", "XMR")
    ADDR_NET_VER_TN: bytes = b"\x35"
    ADDR_INT_NET_VER_TN: bytes = b"\x36"
    SUBADDR_NET_VER_TN: bytes = b"\x3f"


# Configuration for Moonbeam
class MoonbeamConf:
    COIN_NAME: CoinNames = CoinNames("Moonbeam", "GLMR")
    ADDR_SS58_FORMAT: int = 1284


# Configuration for Moonriver
class MoonriverConf:
    COIN_NAME: CoinNames = CoinNames("Moonriver", "MOVR")
    ADDR_SS58_FORMAT: int = 1285


# Configuration for OKEx Chain
class OkexChainConf:
    COIN_NAME: CoinNames = CoinNames("OKExChain", "OKT")
    ADDR_HRP: str = "ex"


# Configuration for Nano
class NanoConf:
    COIN_NAME: CoinNames = CoinNames("Nano", "NANO")
    ADDR_PREFIX: str = "nano_"


# Configuration for Neo
class NeoConf:
    COIN_NAME: CoinNames = CoinNames("NEO", "NEO")
    ADDR_VER: bytes = b"\x17"


# Configuration for Ontology
class OntologyConf:
    COIN_NAME: CoinNames = CoinNames("Ontology", "ONT")
    ADDR_VER: bytes = NeoConf.ADDR_VER


# Configuration for NG
class NineChroniclesGoldConf:
    COIN_NAME: CoinNames = CoinNames("Nine Chronicles Gold", "NCG")


# Configuration for Phala
class PhalaConf:
    COIN_NAME: CoinNames = CoinNames("Phala Network", "PHA")
    ADDR_SS58_FORMAT: int = 30


# Configuration for Plasm
class PlasmConf:
    COIN_NAME: CoinNames = CoinNames("Plasm Network", "PLM")
    ADDR_SS58_FORMAT: int = 5


# Configuration for Polkadot
class PolkadotConf:
    COIN_NAME: CoinNames = CoinNames("Polkadot", "DOT")
    ADDR_SS58_FORMAT: int = 0


# Configuration for Polygon
class PolygonConf:
    COIN_NAME: CoinNames = CoinNames("Polygon", "MATIC")


# Configuration for Ripple
class RippleConf:
    COIN_NAME: CoinNames = CoinNames("Ripple", "XRP")
    P2PKH_NET_VER: bytes = BitcoinConf.P2PKH_NET_VER_MN


# Configuration for Solana
class SolanaConf:
    COIN_NAME: CoinNames = CoinNames("Solana", "SOL")


# Configuration for Sora
class SoraConf:
    COIN_NAME: CoinNames = CoinNames("Sora", "XOR")
    ADDR_SS58_FORMAT: int = 69


# Configuration for Stafi
class StafiConf:
    COIN_NAME: CoinNames = CoinNames("Stafi", "FIS")
    ADDR_SS58_FORMAT: int = 20


# Configuration for Stellar
class StellarConf:
    COIN_NAME: CoinNames = CoinNames("Stellar", "XLM")


# Configuration for Terra
class TerraConf:
    COIN_NAME: CoinNames = CoinNames("Terra", "LUNA")
    ADDR_HRP: str = "terra"


# Configuration for Tezos
class TezosConf:
    COIN_NAME: CoinNames = CoinNames("Tezos", "XTZ")


# Configuration for Theta
class ThetaConf:
    COIN_NAME: CoinNames = CoinNames("Theta Network", "THETA")


# Configuration for Tron
class TronConf:
    COIN_NAME: CoinNames = CoinNames("Tron", "TRX")
    ADDR_PREFIX: bytes = b"\x41"


# Configuration for VeChain
class VeChainConf:
    COIN_NAME: CoinNames = CoinNames("VeChain", "VET")


# Configuration for Zcash
class ZcashConf:
    # Main net
    COIN_NAME_MN: CoinNames = CoinNames("Zcash", "ZEC")
    P2PKH_NET_VER_MN: bytes = b"\x1c\xb8"
    P2SH_NET_VER_MN: bytes = b"\x1c\xbd"
    WIF_NET_VER_MN: bytes = BitcoinConf.WIF_NET_VER_MN
    # Test net
    COIN_NAME_TN: CoinNames = CoinNames("Zcash TestNet", "ZEC")
    P2PKH_NET_VER_TN: bytes = b"\x1d\x25"
    P2SH_NET_VER_TN: bytes = b"\x1c\xba"
    WIF_NET_VER_TN: bytes = BitcoinConf.WIF_NET_VER_TN


# Configuration for Zilliqa
class ZilliqaConf:
    COIN_NAME: CoinNames = CoinNames("Zilliqa", "ZIL")
    ADDR_HRP: str = "zil"
