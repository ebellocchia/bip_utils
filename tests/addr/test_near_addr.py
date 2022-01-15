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
from bip_utils import NearAddr
from tests.addr.test_addr_base import AddrBaseTestHelper
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey

# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"008dc5989dcb090a36b348f7bb236e1fc8e7c2c25d8b0f8221ffa04169cee9e96a",
        "addr_params": {},
        "address": "8dc5989dcb090a36b348f7bb236e1fc8e7c2c25d8b0f8221ffa04169cee9e96a",
    },
    {
        "pub_key": b"00e881e7d40d573405cb90213637261330329a809608220cf01288eefd55156c14",
        "addr_params": {},
        "address": "e881e7d40d573405cb90213637261330329a809608220cf01288eefd55156c14",
    },
    {
        "pub_key": b"0049c93960fd3f49e671b4a712d3e95c5ae3d8e66552cb97879c897374599a22c1",
        "addr_params": {},
        "address": "49c93960fd3f49e671b4a712d3e95c5ae3d8e66552cb97879c897374599a22c1",
    },
    {
        "pub_key": b"b4072e7e5001caf7f7003e03e942fe37bc31184b3395ec9ac8c5bfad4b379f8f",
        "addr_params": {},
        "address": "b4072e7e5001caf7f7003e03e942fe37bc31184b3395ec9ac8c5bfad4b379f8f",
    },
    {
        "pub_key": b"4a39721ffc10430e22720ff8473074938005a5d5781533267e664ad9c1d13284",
        "addr_params": {},
        "address": "4a39721ffc10430e22720ff8473074938005a5d5781533267e664ad9c1d13284",
    },
]


#
# Tests
#
class NearAddrTests(unittest.TestCase):
    # Test encode key
    def test_encode_key(self):
        AddrBaseTestHelper.test_encode_key(self, NearAddr, Ed25519PublicKey, TEST_VECT)

    # Test invalid keys
    def test_invalid_keys(self):
        AddrBaseTestHelper.test_invalid_keys(self,
                                             NearAddr,
                                             {},
                                             TEST_ED25519_ADDR_INVALID_KEY_TYPES,
                                             TEST_VECT_ED25519_PUB_KEY_INVALID)
