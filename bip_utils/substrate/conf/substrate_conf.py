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

# Reference for formats: https://wiki.polkadot.network/docs/build-ss58-registry

# Imports
from bip_utils.conf.common import CoinNames
from bip_utils.substrate.conf.substrate_coin_conf import SubstrateCoinConf


# Configuration for a Acala
SubstrateAcala: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Acala", "ACA"),
    ss58_format=10
)

# Configuration for a Bifrost
SubstrateBifrost: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Bifrost", "BNC"),
    ss58_format=6
)

# Configuration for a ChainX
SubstrateChainX: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("ChainX", "PCX"),
    ss58_format=44
)

# Configuration for a Edgeware
SubstrateEdgeware: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Edgeware", "EDG"),
    ss58_format=7
)

# Configuration for a generic Substrate coin
SubstrateGeneric: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Generic Substrate", ""),
    ss58_format=42
)

# Configuration for Karura
SubstrateKarura: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Karura", "KAR"),
    ss58_format=8
)

# Configuration for Kusama
SubstrateKusama: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Kusama", "KSM"),
    ss58_format=2
)

# Configuration for a Moonbeam
SubstrateMoonbeam: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Moonbeam", "GLMR"),
    ss58_format=1284
)

# Configuration for a Moonriver
SubstrateMoonriver: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Moonriver", "MOVR"),
    ss58_format=1285
)

# Configuration for a Phala
SubstratePhala: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Phala Network", "PHA"),
    ss58_format=30
)

# Configuration for a Plasm
SubstratePlasm: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Plasm Network", "PLM"),
    ss58_format=5
)

# Configuration for Polkadot
SubstratePolkadot: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Polkadot", "DOT"),
    ss58_format=0
)

# Configuration for a Sora
SubstrateSora: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Sora", "XOR"),
    ss58_format=69
)

# Configuration for a Stafi
SubstrateStafi: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=CoinNames("Stafi", "FIS"),
    ss58_format=20
)
