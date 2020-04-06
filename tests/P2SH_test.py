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
from bip_utils import P2SH
from bip_utils import BitcoinConf, LitecoinConf


# Some keys randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
TEST_VECTOR = \
    [
        {
            "pub_key"      : b"039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
            "address"      :  "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["main"],
        },
        {
            "pub_key"      : b"025c3cd8658ff360e3ab7aec091d33d386fd02173fb4d9bd08713dae4b13c9b869",
            "address"      :  "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["main"],
        },
        {
            "pub_key"      : b"0209a795c0603b608bee1bb248832e4d3d311570cd5c16e9840e4c130953f8e327",
            "address"      :  "3LwcWnqXb6f371qkWZRxW9Hbe798zLmpAS",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["main"],
        },
        {
            "pub_key"      : b"0353b6be278e86fafce63117f56ed8db27e360e74a9b9e07d507cf560c85d46dea",
            "address"      :  "3NmSLfUSMB3zstyMRMzfFmkPXMufrhsuAc",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["main"],
        },
        {
            "pub_key"      : b"03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803",
            "address"      :  "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["test"],
        },
        {
            "pub_key"      : b"030de4c268df782aa1543371c19988274686b6bb5acf5692b208715cb16ec44fff",
            "address"      :  "2Mtrpqq7cQznHw9wYnsSKroTdZ6u3fsB4kZ",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["test"],
        },
        {
            "pub_key"      : b"02fb62cd50fc394d703242c89573e33fe146dc30a7c703582757b739246deeabf2",
            "address"      :  "2N7AZigbQQje53NybX2AuD9amuF3Kfr5Z8h",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["test"],
        },
        {
            "pub_key"      : b"020fc068a25f777f505d6f677a1f865e50809112790693e0d246691d9876a7483f",
            "address"      :  "2N31gWk3ZQygoANPPn39qC9ZQTc9jhqicsE",
            "net_addr_ver" :  BitcoinConf.P2SH_NET_VER["test"],
        },
    ]


#
# Tests
#
class P2SHTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECTOR:
            # Test decoder
            self.assertEqual(test["address"], P2SH.ToAddress(binascii.unhexlify(test["pub_key"]), test["net_addr_ver"]))
            self.assertEqual(test["address"], P2SH.ToAddress(binascii.unhexlify(test["pub_key"]), test["net_addr_ver"]))


# Run test if executed
if __name__ == "__main__":
    unittest.main()
