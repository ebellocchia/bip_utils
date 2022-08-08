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
import os
import unittest

from bip_utils import Bip32KeyNetVersions
from bip_utils.bip.bip32.bip32_key_net_ver import Bip32KeyNetVersionsConst


#
# Tests
#
class Bip32KeyNetVersionsTests(unittest.TestCase):
    # Basic test
    def test_basic(self):
        key_net_ver_priv = os.urandom(Bip32KeyNetVersionsConst.KEY_NET_VERSION_BYTE_LEN)
        key_net_ver_pub = os.urandom(Bip32KeyNetVersionsConst.KEY_NET_VERSION_BYTE_LEN)
        key_net_ver = Bip32KeyNetVersions(key_net_ver_priv, key_net_ver_pub)
        self.assertEqual(key_net_ver.Length(), Bip32KeyNetVersionsConst.KEY_NET_VERSION_BYTE_LEN)
        self.assertEqual(key_net_ver.Public(), key_net_ver_priv)
        self.assertEqual(key_net_ver.Private(), key_net_ver_pub)

    # Test invalid parameters
    def test_invalid_parameters(self):
        net_ver_len = Bip32KeyNetVersionsConst.KEY_NET_VERSION_BYTE_LEN
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00" * (net_ver_len - 1), b"\x00\x00\x00\x00")
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00" * (net_ver_len + 1), b"\x00\x00\x00\x00")
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00\x00\x00\x00", b"\x00" * (net_ver_len - 1))
        self.assertRaises(ValueError, Bip32KeyNetVersions, b"\x00\x00\x00\x00", b"\x00" * (net_ver_len + 1))
