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
from bip_utils.coin_conf import *
from bip_utils.substrate.conf.substrate_coin_conf import SubstrateCoinConf


# Configuration for a Acala
SubstrateAcala: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=AcalaConf.COIN_NAME,
    ss58_format=AcalaConf.ADDR_SS58_FORMAT,
)

# Configuration for a Bifrost
SubstrateBifrost: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=BifrostConf.COIN_NAME,
    ss58_format=BifrostConf.ADDR_SS58_FORMAT,
)

# Configuration for a ChainX
SubstrateChainX: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=ChainXConf.COIN_NAME,
    ss58_format=ChainXConf.ADDR_SS58_FORMAT,
)

# Configuration for a Edgeware
SubstrateEdgeware: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=EdgewareConf.COIN_NAME,
    ss58_format=EdgewareConf.ADDR_SS58_FORMAT,
)

# Configuration for a generic Substrate coin
SubstrateGeneric: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=GenericSubstrateConf.COIN_NAME,
    ss58_format=GenericSubstrateConf.ADDR_SS58_FORMAT,
)

# Configuration for Karura
SubstrateKarura: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=KaruraConf.COIN_NAME,
    ss58_format=KaruraConf.ADDR_SS58_FORMAT,
)

# Configuration for Kusama
SubstrateKusama: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=KusamaConf.COIN_NAME,
    ss58_format=KusamaConf.ADDR_SS58_FORMAT,
)

# Configuration for a Moonbeam
SubstrateMoonbeam: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=MoonbeamConf.COIN_NAME,
    ss58_format=MoonbeamConf.ADDR_SS58_FORMAT,
)

# Configuration for a Moonriver
SubstrateMoonriver: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=MoonriverConf.COIN_NAME,
    ss58_format=MoonriverConf.ADDR_SS58_FORMAT,
)

# Configuration for a Phala
SubstratePhala: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=PhalaConf.COIN_NAME,
    ss58_format=PhalaConf.ADDR_SS58_FORMAT,
)

# Configuration for a Plasm
SubstratePlasm: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=PlasmConf.COIN_NAME,
    ss58_format=PlasmConf.ADDR_SS58_FORMAT,
)

# Configuration for Polkadot
SubstratePolkadot: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=PolkadotConf.COIN_NAME,
    ss58_format=PolkadotConf.ADDR_SS58_FORMAT,
)

# Configuration for a Sora
SubstrateSora: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=SoraConf.COIN_NAME,
    ss58_format=SoraConf.ADDR_SS58_FORMAT,
)

# Configuration for a Stafi
SubstrateStafi: SubstrateCoinConf = SubstrateCoinConf(
    coin_name=StafiConf.COIN_NAME,
    ss58_format=StafiConf.ADDR_SS58_FORMAT,
)
