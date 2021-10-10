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
from bip_utils import Monero
from tests.benchmark_tests_base import BenchmarkTestsBase


# Monero tests class
class MoneroTests(BenchmarkTestsBase):
    # Run test
    def _RunTest(self,
                 seed_bytes: bytes) -> None:
        for i in range(0, self.m_test_itr_num):
            monero_ctx = Monero.FromSeed(seed_bytes)

            for j in range(0, self.m_test_cache_num):
                monero_ctx.PrimaryAddress()
                monero_ctx.PublicSpendKey().RawCompressed().ToHex()
                monero_ctx.PublicSpendKey().RawUncompressed().ToHex()
                monero_ctx.PublicViewKey().RawCompressed().ToHex()
                monero_ctx.PublicViewKey().RawUncompressed().ToHex()
                monero_ctx.PrivateSpendKey().Raw().ToHex()
                monero_ctx.PrivateViewKey().Raw().ToHex()
                monero_ctx.Subaddress(i)
