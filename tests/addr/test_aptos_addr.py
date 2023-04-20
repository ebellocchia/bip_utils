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
from bip_utils import AptosAddr, AptosAddrDecoder, AptosAddrEncoder
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519PublicKey


# Some random public keys
TEST_VECT = [
    {
        "pub_key": b"00c2e2d2b06eff37720eaa9d3fc59e83404c154c7517e647b115aaedb6068deacf",
        "address_dec": b"59d607c50d227dc2d642221e72c7612fd0887b4805b10ab9351d840da0548350",
        "address_params": {},
        "address": "0x59d607c50d227dc2d642221e72c7612fd0887b4805b10ab9351d840da0548350",
    },
    {
        "pub_key": b"0065091c6b34cf557caa07ed9d65887e59a07fd75f4670dd9baf7920c520da3804",
        "address_dec": b"03aa1ceed625af8407d25e5894a165272b5d196dcdb8dc66456d2ac039bcf198",
        "address_params": {},
        "address": "0x3aa1ceed625af8407d25e5894a165272b5d196dcdb8dc66456d2ac039bcf198",
    },
    {
        "pub_key": b"0018c3ffaf12ab774572e875b24316991b673c20297d52951970ed7b853e48ce44",
        "address_dec": b"c2b1d2a053a90037c5226e1f346df90b354720121818c787d363ac4e011b9193",
        "address_params": {},
        "address": "0xc2b1d2a053a90037c5226e1f346df90b354720121818c787d363ac4e011b9193",
    },
    {
        "pub_key": b"1d86e698067245ec022bc3405bfeeeb9a0444388bc1a325486ff2ae0a39df61b",
        "address_dec": b"0e8d7c29f28f4d72da95d1d8784d53c4240768ec916cc7ce60ef3c80d6509f07",
        "address_params": {},
        "address": "0xe8d7c29f28f4d72da95d1d8784d53c4240768ec916cc7ce60ef3c80d6509f07",
    },
    {
        "pub_key": b"e2db08dab9943141b6456d39c4506be647de9eedd912192dfd60bc9c9277cffe",
        "address_dec": b"071e1d7330597e99001aad667d6deea321e95771d6975dd66bfb185f5cfd7d58",
        "address_params": {},
        "address": "0x71e1d7330597e99001aad667d6deea321e95771d6975dd66bfb185f5cfd7d58",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid encoding
    "0xc2b1d2a053a90037c5226e1f346df90b354720121818c787d363tc4e011b9193",
    # Invalid prefix
    "1xc2b1d2a053a90037c5226e1f346df90b354720121818c787d363ac4e011b9193",
    # Invalid lengths
    "0xc2b1d2a053a90037c5226e1f346df90b354720121818c787d363ac4e011b91930",
]


#
# Tests
#
class AptosAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(AptosAddrEncoder, Ed25519PublicKey, TEST_VECT)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(AptosAddrDecoder, TEST_VECT)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(AptosAddrDecoder, {}, TEST_VECT_DEC_INVALID)

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            AptosAddrEncoder,
            {},
            TEST_ED25519_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(AptosAddr is AptosAddrEncoder)
