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
import binascii
import unittest


#
# Base test class for IAddrDecoder and IAddrEncoder child classes, which share the same tests
#
class AddrBaseTests(unittest.TestCase):
    # Test encode key
    def _test_encode_key(self, addr_enc_class, pub_key_class, test_vector):
        for test in test_vector:
            key_bytes = binascii.unhexlify(test["pub_key"])

            # Test with bytes and public key object
            self.assertEqual(test["address"], addr_enc_class.EncodeKey(key_bytes,
                                                                       **test["address_params"]))
            self.assertEqual(test["address"], addr_enc_class.EncodeKey(pub_key_class.FromBytes(key_bytes),
                                                                       **test["address_params"]))

    # Test decode address
    def _test_decode_addr(self, addr_dec_class, test_vector):
        for test in test_vector:
            dec_bytes = binascii.unhexlify(test["address_dec"])
            self.assertEqual(dec_bytes, addr_dec_class.DecodeAddr(test["address"],
                                                                  **test["address_params"]))

    # Test invalid decoding
    def _test_invalid_dec(self, addr_dec_class, addr_params, test_vector):
        for addr in test_vector:
            self.assertRaises(ValueError, addr_dec_class.DecodeAddr, addr, **addr_params)

    # Test invalid keys
    def _test_invalid_keys(self, addr_enc_class, addr_params, test_vector_inv_types, test_vector_inv_keys):
        # Invalid key types
        for key in test_vector_inv_types:
            self.assertRaises(TypeError, addr_enc_class.EncodeKey, key, **addr_params)

        # Invalid public keys
        for key in test_vector_inv_keys:
            self.assertRaises(ValueError, addr_enc_class.EncodeKey, key, **addr_params)

    # Test invalid parameters (decoding)
    def _test_invalid_params_dec(self, addr_dec_class, err_params, ex_type):
        self.assertRaises(ex_type, addr_dec_class.DecodeAddr, "", **err_params)

    # Test invalid parameters (encoding)
    def _test_invalid_params_enc(self, addr_enc_class, err_params, ex_type):
        self.assertRaises(ex_type, addr_enc_class.EncodeKey, b"", **err_params)
