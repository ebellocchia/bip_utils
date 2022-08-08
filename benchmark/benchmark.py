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
from enum import Enum, auto, unique
from typing import Dict, Type

from bip_utils import Bip39SeedGenerator
from tests import (BenchmarkTestsBase, Ed25519Blake2bTests, Ed25519KholawTests,
                   Ed25519Tests, MoneroTests, Nist256p1Tests, Secp256k1Tests,
                   SubstrateTests)


# Test types
@unique
class TestTypes(Enum):
    SECP256K1 = auto()
    NIST256P1 = auto()
    ED25519 = auto()
    ED25519_BLAKE2B = auto()
    ED25519_KHOLAW = auto()
    SUBSTRATE = auto()
    MONERO = auto()


# Tests constants
class TestsConsts:
    # Test type to class type
    TEST_TYPE_TO_CLASS_TYPE: Dict[TestTypes, Type[BenchmarkTestsBase]] = {
        TestTypes.SECP256K1: Secp256k1Tests,
        TestTypes.NIST256P1: Nist256p1Tests,
        TestTypes.ED25519: Ed25519Tests,
        TestTypes.ED25519_BLAKE2B: Ed25519Blake2bTests,
        TestTypes.ED25519_KHOLAW: Ed25519KholawTests,
        TestTypes.SUBSTRATE: SubstrateTests,
        TestTypes.MONERO: MoneroTests,
    }


# Tests configuration
class TestsConf:
    TEST_NUM: int = 5
    TEST_ITR_NUM: int = 3000
    TEST_CACHE_NUM: int = 50
    TEST_TYPE: TestTypes = TestTypes.SECP256K1


# Main function
def main() -> None:
    # Print info
    print("\nBenchmark started!")
    print("Configuration:")
    print(f"  - Test type: {TestsConf.TEST_TYPE}")
    print(f"  - Number of tests: {TestsConf.TEST_NUM}")
    print(f"  - Number of iterations for each test: {TestsConf.TEST_ITR_NUM}")
    print(f"  - Number of iterations for caching: {TestsConf.TEST_CACHE_NUM}\n")

    # Generate a seed
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "\
               "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Get tests class type
    tests_cls = TestsConsts.TEST_TYPE_TO_CLASS_TYPE[TestsConf.TEST_TYPE]

    # Run tests
    tests = tests_cls(TestsConf.TEST_NUM,
                      TestsConf.TEST_ITR_NUM,
                      TestsConf.TEST_CACHE_NUM)
    tests.RunTests(seed_bytes)

    # Print average time
    print("\nBenchmark completed.")
    print(f"Average time: {tests.GetAverageTime():.0f}ms\n")


# Execute main
if __name__ == "__main__":
    main()
