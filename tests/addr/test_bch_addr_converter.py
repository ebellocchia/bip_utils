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
import unittest

from bip_utils import BchAddrConverter


# Some random addresses
TEST_VECT = [
    {
        "address": "bitcoincash:qp90dvzptg759efdcd93s4dkdw0vuhlkmqlch7letq",
        "new_hrp": "simpleledger",
        "new_net_ver": None,
        "conv_address": "simpleledger:qp90dvzptg759efdcd93s4dkdw0vuhlkmqnru92e47",
    },
    {
        "address": "simpleledger:qzg7fqptr7sxtgngrskvrh5qgm28ycx4v5wcac3h4h",
        "new_hrp": "ecash",
        "new_net_ver": None,
        "conv_address": "ecash:qzg7fqptr7sxtgngrskvrh5qgm28ycx4v5mwzgldd7",
    },
    {
        "address": "ecash:qre0s25cd0y33c28dwn4yqmgv0el64ydsvm65g8ulz",
        "new_hrp": "ergon",
        "new_net_ver": None,
        "conv_address": "ergon:qre0s25cd0y33c28dwn4yqmgv0el64ydsvrv45yggc",
    },
    {
        "address": "bitcoincash:qq8px5j8fyag0l86a0vtksfxk4g0wknezqm8tjj9wd",
        "new_hrp": "customprefix",
        "new_net_ver": b"\x01",
        "conv_address": "customprefix:qy8px5j8fyag0l86a0vtksfxk4g0wknezq84f9r2lc",
    },
    {
        "address": "bitcoincash:qp2u0wlzct3lqkku6xjz8qkj62c02hgpps35llu5ey",
        "new_hrp": "customprefix",
        "new_net_ver": b"\x02",
        "conv_address": "customprefix:qf2u0wlzct3lqkku6xjz8qkj62c02hgppsuyj8ygx3",
    },
]


#
# Tests
#
class BchAddrConverterTests(unittest.TestCase):
    # Run all tests in test vector
    def test_vector(self):
        for test in TEST_VECT:
            conv_addr = BchAddrConverter.Convert(test["address"], test["new_hrp"], test["new_net_ver"])
            self.assertEqual(test["conv_address"], conv_addr)
