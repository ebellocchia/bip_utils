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
from typing import Type
from bip_utils import Bip44Changes
from bip_utils.bip.bip44_base import Bip44Base
from bip_utils.bip.conf.common import BipCoins
from tests.benchmark_tests_base import BenchmarkTestsBase


# Bip44 tests class
class Bip44Tests(BenchmarkTestsBase):

    m_bip_cls: Type[Bip44Base]
    m_bip_coin: BipCoins

    # Constructor
    def __init__(self,
                 bip_cls: Type[Bip44Base],
                 bip_coin: BipCoins,
                 test_num: int,
                 test_itr_num: int,
                 test_cache_num: int) -> None:
        super().__init__(test_num, test_itr_num, test_cache_num)
        self.m_bip_cls = bip_cls
        self.m_bip_coin = bip_coin

    # Run test
    def _RunTest(self,
                 seed_bytes: bytes) -> None:
        for i in range(0, self.m_test_itr_num):
            bip44_ctx = self.m_bip_cls.FromSeed(seed_bytes, self.m_bip_coin)
            bip44_chg = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)

            for j in range(0, self.m_test_cache_num):
                bip44_chg.PublicKey().ToAddress()
                bip44_chg.PublicKey().ToExtended()
                bip44_chg.PrivateKey().ToExtended()
                bip44_chg.PublicKey().RawCompressed().ToHex()
                bip44_chg.PublicKey().RawUncompressed().ToHex()
                bip44_chg.PrivateKey().Raw().ToHex()

            bip44_addr = bip44_chg.AddressIndex(i)

            for j in range(0, self.m_test_cache_num):
                bip44_addr.PublicKey().ToAddress()
                bip44_addr.PublicKey().ToExtended()
                bip44_addr.PrivateKey().ToExtended()
                bip44_addr.PublicKey().RawCompressed().ToHex()
                bip44_addr.PublicKey().RawUncompressed().ToHex()
                bip44_addr.PrivateKey().Raw().ToHex()
