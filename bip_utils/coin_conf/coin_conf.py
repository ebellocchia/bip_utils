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

"""Module with generic coins configuration."""

# Imports
from bip_utils.utils.conf import CoinNames


class AcalaConf:
    """Configuration for a Acala."""

    COIN_NAME: CoinNames = CoinNames("Acala", "ACA")
    ADDR_SS58_FORMAT: int = 10


class AlgorandConf:
    """Configuration for Algorand."""

    COIN_NAME: CoinNames = CoinNames("Algorand", "ALGO")


class AvaxCChainConf:
    """Configuration for Avax C-Chain."""

    COIN_NAME: CoinNames = CoinNames("Avax C-Chain", "AVAX")


class AvaxPChainConf:
    """Configuration for Avax P-Chain."""

    COIN_NAME: CoinNames = CoinNames("Avax P-Chain", "AVAX")
    ADDR_HRP: str = "avax"
    ADDR_PREFIX: str = "P-"


class AvaxXChainConf:
    """Configuration for Avax X-Chain."""

    COIN_NAME: CoinNames = CoinNames("Avax X-Chain", "AVAX")
    ADDR_HRP: str = "avax"
    ADDR_PREFIX: str = "X-"


class BandProtocolConf:
    """Configuration for Band Protocol."""

    COIN_NAME: CoinNames = CoinNames("Band Protocol", "BAND")
    ADDR_HRP: str = "band"


class BifrostConf:
    """Configuration for a Bifrost."""

    COIN_NAME: CoinNames = CoinNames("Bifrost", "BNC")
    ADDR_SS58_FORMAT: int = 6


class BinanceChainConf:
    """Configuration for Binance Chain."""

    COIN_NAME: CoinNames = CoinNames("Binance Chain", "BNB")
    ADDR_HRP: str = "bnb"


class BinanceSmartChainConf:
    """Configuration for Binance Smart Chain."""

    COIN_NAME: CoinNames = CoinNames("Binance Smart Chain", "BNB")


class BitcoinConf:
    """Configuration for Bitcoin."""

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


class BitcoinCashConf:
    """Configuration for Bitcoin Cash."""

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


class BitcoinSvConf:
    """Configuration for BitcoinSV."""

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


class ChainXConf:
    """Configuration for a ChainX."""

    COIN_NAME: CoinNames = CoinNames("ChainX", "PCX")
    ADDR_SS58_FORMAT: int = 44


class CosmosConf:
    """Configuration for Cosmos."""

    COIN_NAME: CoinNames = CoinNames("Cosmos", "ATOM")
    ADDR_HRP: str = "cosmos"


class DashConf:
    """Configuration for Dash."""

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


class DogecoinConf:
    """Configuration for Dogecoin."""

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


class EdgewareConf:
    """Configuration for a Edgeware."""

    COIN_NAME: CoinNames = CoinNames("Edgeware", "EDG")
    ADDR_SS58_FORMAT: int = 7


class ElrondConf:
    """Configuration for Elrond."""

    COIN_NAME: CoinNames = CoinNames("Elrond eGold", "eGLD")
    ADDR_HRP: str = "erd"


class EosConf:
    """Configuration for Eos."""

    COIN_NAME: CoinNames = CoinNames("EOS", "EOS")
    ADDR_PREFIX: str = "EOS"


class EthereumConf:
    """Configuration for Ethereum."""

    COIN_NAME: CoinNames = CoinNames("Ethereum", "ETH")
    ADDR_PREFIX: str = "0x"


class EthereumClassicConf:
    """Configuration for Ethereum Classic."""

    COIN_NAME: CoinNames = CoinNames("Ethereum Classic", "ETC")


class FantomOperaConf:
    """Configuration for Fantom Opera."""

    COIN_NAME: CoinNames = CoinNames("Fantom Opera", "FTM")


class FilecoinConf:
    """Configuration for Filecoin."""

    COIN_NAME: CoinNames = CoinNames("Filecoin", "FIL")
    ADDR_PREFIX: str = "f"


class GenericSubstrateConf:
    """Configuration for a generic Substrate coin."""

    COIN_NAME: CoinNames = CoinNames("Generic Substrate", "")
    ADDR_SS58_FORMAT: int = 42


class HarmonyOneConf:
    """Configuration for Harmony One."""

    COIN_NAME: CoinNames = CoinNames("Harmony One", "ONE")
    ADDR_HRP: str = "one"


class HuobiChainConf:
    """Configuration for Huobi Chain."""

    COIN_NAME: CoinNames = CoinNames("Huobi Token", "HT")


class IrisNetConf:
    """Configuration for IRISnet."""

    COIN_NAME: CoinNames = CoinNames("IRIS Network", "IRIS")
    ADDR_HRP: str = "iaa"


class KaruraConf:
    """Configuration for Karura."""

    COIN_NAME: CoinNames = CoinNames("Karura", "KAR")
    ADDR_SS58_FORMAT: int = 8


class KavaConf:
    """Configuration for Kava."""

    COIN_NAME: CoinNames = CoinNames("Kava", "KAVA")
    ADDR_HRP: str = "kava"


class KusamaConf:
    """Configuration for Kusama."""

    COIN_NAME: CoinNames = CoinNames("Kusama", "KSM")
    ADDR_SS58_FORMAT: int = 2


class LitecoinConf:
    """Configuration for Litecoin."""

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


class MoneroConf:
    """Configuration for Monero."""

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


class MoonbeamConf:
    """Configuration for Moonbeam."""

    COIN_NAME: CoinNames = CoinNames("Moonbeam", "GLMR")
    ADDR_SS58_FORMAT: int = 1284


class MoonriverConf:
    """Configuration for Moonriver."""

    COIN_NAME: CoinNames = CoinNames("Moonriver", "MOVR")
    ADDR_SS58_FORMAT: int = 1285


class OkexChainConf:
    """Configuration for OKEx Chain."""

    COIN_NAME: CoinNames = CoinNames("OKExChain", "OKT")
    ADDR_HRP: str = "ex"


class NanoConf:
    """Configuration for Nano."""

    COIN_NAME: CoinNames = CoinNames("Nano", "NANO")
    ADDR_PREFIX: str = "nano_"


class NeoConf:
    """Configuration for Neo."""

    COIN_NAME: CoinNames = CoinNames("NEO", "NEO")
    ADDR_VER: bytes = b"\x17"


class OntologyConf:
    """Configuration for Ontology."""

    COIN_NAME: CoinNames = CoinNames("Ontology", "ONT")
    ADDR_VER: bytes = NeoConf.ADDR_VER


class NineChroniclesGoldConf:
    """Configuration for NG."""

    COIN_NAME: CoinNames = CoinNames("Nine Chronicles Gold", "NCG")


class PhalaConf:
    """Configuration for Phala."""

    COIN_NAME: CoinNames = CoinNames("Phala Network", "PHA")
    ADDR_SS58_FORMAT: int = 30


class PlasmConf:
    """Configuration for Plasm."""

    COIN_NAME: CoinNames = CoinNames("Plasm Network", "PLM")
    ADDR_SS58_FORMAT: int = 5


class PolkadotConf:
    """Configuration for Polkadot."""

    COIN_NAME: CoinNames = CoinNames("Polkadot", "DOT")
    ADDR_SS58_FORMAT: int = 0


class PolygonConf:
    """Configuration for Polygon."""

    COIN_NAME: CoinNames = CoinNames("Polygon", "MATIC")


class RippleConf:
    """Configuration for Ripple."""

    COIN_NAME: CoinNames = CoinNames("Ripple", "XRP")
    P2PKH_NET_VER: bytes = BitcoinConf.P2PKH_NET_VER_MN


class SolanaConf:
    """Configuration for Solana."""

    COIN_NAME: CoinNames = CoinNames("Solana", "SOL")


class SoraConf:
    """Configuration for Sora."""

    COIN_NAME: CoinNames = CoinNames("Sora", "XOR")
    ADDR_SS58_FORMAT: int = 69


class StafiConf:
    """Configuration for Stafi."""

    COIN_NAME: CoinNames = CoinNames("Stafi", "FIS")
    ADDR_SS58_FORMAT: int = 20


class StellarConf:
    """Configuration for Stellar."""

    COIN_NAME: CoinNames = CoinNames("Stellar", "XLM")


class TerraConf:
    """Configuration for Terra."""

    COIN_NAME: CoinNames = CoinNames("Terra", "LUNA")
    ADDR_HRP: str = "terra"


class TezosConf:
    """Configuration for Tezos."""

    COIN_NAME: CoinNames = CoinNames("Tezos", "XTZ")


class ThetaConf:
    """Configuration for Theta."""

    COIN_NAME: CoinNames = CoinNames("Theta Network", "THETA")


class TronConf:
    """Configuration for Tron."""

    COIN_NAME: CoinNames = CoinNames("Tron", "TRX")
    ADDR_PREFIX: bytes = b"\x41"


class VeChainConf:
    """Configuration for VeChain."""

    COIN_NAME: CoinNames = CoinNames("VeChain", "VET")


class ZcashConf:
    """Configuration for Zcash."""

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


class ZilliqaConf:
    """Configuration for Zilliqa."""

    COIN_NAME: CoinNames = CoinNames("Zilliqa", "ZIL")
    ADDR_HRP: str = "zil"
