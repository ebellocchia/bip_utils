# Copyright (c) 2020 Emanuele Bellocchia
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
import binascii
import unittest
from bip_utils import BitcoinConf, LitecoinConf, P2WPKH


# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "pub_key"      : b"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
            "address"      :  "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"0299b4cb4809f52dac21bbd8c997d8bf052cf4d68bfe966c638c312fbfff636e17",
            "address"      :  "bc1qtet8q6cd5vqm0zjfcfm8mfsydju0a29ggqrmu9",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"031c34a6bce9676e0b011c93bcf8a2d1007add7ce07f9a502a537f0fee56325944",
            "address"      :  "bc1q8txvqq8kr0nhkatkrmeg7zaj45zpsef2ylc9pq",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"0390d1feb19684674564df87854f3892d9e8a7d3551148c2f299a75d262c950ee0",
            "address"      :  "bc1qrz46a4gt0sghvvyt4gy5kp2rswmhtufv6sdq9v",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["main"],
        },
        {
            "pub_key"      : b"02339193c34cd8ecb21ebd48af64ead71d78213470d61d7274f932489d6ba21bd3",
            "address"      :  "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"03443a4f06e4182fe7f7020318cc394ffdb5517e3ad31991f57252b631ac9df33a",
            "address"      :  "tb1qextge928njsn94qu5jhc80uyx3wpz0fjqneen4",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"02b396686039259ba12198413122c86f5375932ca0be7e052e48107654eb8b097e",
            "address"      :  "tb1qfvczjgwnc6l4tr4ee8vlffr6hznf7u28xnm2yh",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["test"],
        },
        {
            "pub_key"      : b"034f8b2f463fa3fe8e514baf6e2d98c3bc895a22f4d0e279bbb9bc846374939fb3",
            "address"      :  "tb1q4kestxh2w7r7h5hxvn4pn2qv2dldvylgj6t2kr",
            "net_addr_ver" :  BitcoinConf.P2WPKH_NET_VER["test"],
        },
    ]


#
# Tests
#
class P2WPKHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            self.assertEqual(test["address"], P2WPKH.ToAddress(binascii.unhexlify(test["pub_key"]), test["net_addr_ver"]))


# Run test if executed
if __name__ == "__main__":
    unittest.main()
