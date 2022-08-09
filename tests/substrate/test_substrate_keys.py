# Copyright (c) 2022 Emanuele Bellocchia
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

from bip_utils import (
    DataBytes, Sr25519PrivateKey, Sr25519PublicKey, SubstrateKeyError, SubstratePrivateKey, SubstratePublicKey
)
from bip_utils.substrate.conf.substrate_conf import SubstrateConf
from tests.ecc.test_ecc import (
    TEST_ED25519_BLAKE2B_PRIV_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PRIV_KEY,
    TEST_ED25519_MONERO_PUB_KEY, TEST_ED25519_PRIV_KEY, TEST_ED25519_PUB_KEY, TEST_NIST256P1_PRIV_KEY,
    TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PRIV_KEY, TEST_SECP256K1_PUB_KEY, TEST_SR25519_PRIV_KEY,
    TEST_SR25519_PUB_KEY, TEST_VECT_SR25519_PRIV_KEY_INVALID, TEST_VECT_SR25519_PUB_KEY_INVALID
)


# Test address
TEST_ADDRESS = "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo"


#
# Tests
#
class SubstrateKeysTests(unittest.TestCase):
    # Test private key
    def test_priv_key(self):
        # FromBytesOrKeyObject (object)
        self.__test_priv_key_obj(SubstratePrivateKey.FromBytesOrKeyObject(TEST_SR25519_PRIV_KEY, SubstrateConf.Polkadot))
        # FromBytesOrKeyObject (bytes)
        self.__test_priv_key_obj(SubstratePrivateKey.FromBytesOrKeyObject(TEST_SR25519_PRIV_KEY.Raw().ToBytes(), SubstrateConf.Polkadot))
        # FromBytes
        self.__test_priv_key_obj(SubstratePrivateKey.FromBytes(TEST_SR25519_PRIV_KEY.Raw().ToBytes(), SubstrateConf.Polkadot))

    # Test public key
    def test_pub_key(self):
        # FromBytesOrKeyObject (object)
        self.__test_pub_key_obj(SubstratePublicKey.FromBytesOrKeyObject(TEST_SR25519_PUB_KEY, SubstrateConf.Polkadot))
        # FromBytesOrKeyObject (compressed)
        self.__test_pub_key_obj(SubstratePublicKey.FromBytesOrKeyObject(TEST_SR25519_PUB_KEY.RawCompressed().ToBytes(), SubstrateConf.Polkadot))
        # FromBytesOrKeyObject (uncompressed)
        self.__test_pub_key_obj(SubstratePublicKey.FromBytesOrKeyObject(TEST_SR25519_PUB_KEY.RawUncompressed().ToBytes(), SubstrateConf.Polkadot))
        # FromBytes (compressed)
        self.__test_pub_key_obj(SubstratePublicKey.FromBytes(TEST_SR25519_PUB_KEY.RawCompressed().ToBytes(), SubstrateConf.Polkadot))
        # FromBytes (uncompressed)
        self.__test_pub_key_obj(SubstratePublicKey.FromBytes(TEST_SR25519_PUB_KEY.RawUncompressed().ToBytes(), SubstrateConf.Polkadot))

    # Test invalid parameters
    def test_invalid_params(self):
        # Private key
        for key in (TEST_ED25519_PRIV_KEY, TEST_ED25519_BLAKE2B_PRIV_KEY, TEST_ED25519_MONERO_PRIV_KEY,
                    TEST_NIST256P1_PRIV_KEY, TEST_SECP256K1_PRIV_KEY):
            self.assertRaises(TypeError, SubstratePrivateKey, key, SubstrateConf.Polkadot)
        # Public key
        for key in (TEST_ED25519_PUB_KEY, TEST_ED25519_BLAKE2B_PUB_KEY, TEST_ED25519_MONERO_PUB_KEY,
                    TEST_NIST256P1_PUB_KEY, TEST_SECP256K1_PUB_KEY):
            self.assertRaises(TypeError, SubstratePublicKey, key, SubstrateConf.Polkadot)

    # Test invalid keys
    def test_invalid_keys(self):
        # Invalid private keys
        for test in TEST_VECT_SR25519_PRIV_KEY_INVALID:
            self.assertRaises(SubstrateKeyError, SubstratePrivateKey.FromBytesOrKeyObject, binascii.unhexlify(test), SubstrateConf.Polkadot)
            self.assertRaises(SubstrateKeyError, SubstratePrivateKey.FromBytes, binascii.unhexlify(test), SubstrateConf.Polkadot)
        # Invalid public keys
        for test in TEST_VECT_SR25519_PUB_KEY_INVALID:
            self.assertRaises(SubstrateKeyError, SubstratePublicKey.FromBytesOrKeyObject, binascii.unhexlify(test), SubstrateConf.Polkadot)
            self.assertRaises(SubstrateKeyError, SubstratePublicKey.FromBytes, binascii.unhexlify(test), SubstrateConf.Polkadot)

    # Test private key object
    def __test_priv_key_obj(self, priv_key):
        # Object
        self.assertTrue(isinstance(priv_key.KeyObject(), Sr25519PrivateKey))
        self.assertTrue(isinstance(priv_key.Raw(), DataBytes))
        # Key
        self.assertEqual(TEST_SR25519_PRIV_KEY.Raw().ToBytes(), priv_key.Raw().ToBytes())
        # Public key associated to the private one
        self.__test_pub_key_obj(priv_key.PublicKey())

    # Test public key object
    def __test_pub_key_obj(self, pub_key):
        # Object
        self.assertTrue(isinstance(pub_key.KeyObject(), Sr25519PublicKey))
        self.assertTrue(isinstance(pub_key.RawCompressed(), DataBytes))
        self.assertTrue(isinstance(pub_key.RawUncompressed(), DataBytes))
        # Keys
        self.assertEqual(TEST_SR25519_PUB_KEY.RawCompressed().ToBytes(), pub_key.RawCompressed().ToBytes())
        self.assertEqual(TEST_SR25519_PUB_KEY.RawUncompressed().ToBytes(), pub_key.RawUncompressed().ToBytes())
        # Address
        self.assertEqual(TEST_ADDRESS, pub_key.ToAddress())
