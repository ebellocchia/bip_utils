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
from abc import ABC, abstractmethod
from typing import List

from codetiming import Timer


# Benchmark tests base class
class BenchmarkTestsBase(ABC):

    m_test_num: int
    m_test_itr_num: int
    m_test_cache_num: int
    m_test_elapsed_times: List[float]

    # Constructor
    def __init__(self,
                 test_num: int,
                 test_itr_num: int,
                 test_cache_num: int) -> None:
        self.m_test_num = test_num
        self.m_test_itr_num = test_itr_num
        self.m_test_cache_num = test_cache_num
        self.m_test_elapsed_times = []

    # Run tests
    def RunTests(self,
                 seed_bytes: bytes) -> None:
        self.m_test_elapsed_times = []

        for t in range(0, self.m_test_num):
            # Start timer
            tmr = Timer(name=type(self).__name__, text="{name} - Elapsed time: {milliseconds:.0f}ms")
            tmr.start()

            # Run tests
            self._RunTest(seed_bytes)

            # Stop timer
            self.m_test_elapsed_times.append(tmr.stop())

    # Get elapsed times
    def GetElapsedTimes(self) -> List[float]:
        return self.m_test_elapsed_times

    # Get average time
    def GetAverageTime(self) -> float:
        return (1000.0 * sum(self.m_test_elapsed_times)) / len(self.m_test_elapsed_times)

    # Run test
    @abstractmethod
    def _RunTest(self,
                 seed_bytes: bytes) -> None:
        pass
