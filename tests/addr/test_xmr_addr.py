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

from bip_utils import (
    CoinsConf, XmrAddr, XmrAddrDecoder, XmrAddrEncoder, XmrIntegratedAddr, XmrIntegratedAddrDecoder,
    XmrIntegratedAddrEncoder
)
from bip_utils.addr.xmr_addr import XmrAddrConst
from tests.addr.test_addr_base import AddrBaseTests
from tests.addr.test_addr_const import TEST_ED25519_MONERO_ADDR_INVALID_KEY_TYPES
from tests.ecc.test_ecc import TEST_ED25519_MONERO_PUB_KEY, TEST_VECT_ED25519_PUB_KEY_INVALID, Ed25519MoneroPublicKey


# Some random public keys
# Verified with: https://xmr.llcoins.net/addresstests.html
TEST_VECT = [
    {
        "pub_key": b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422",
        "address_dec": b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422"
                       b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
        },
        "address": "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5UhSCham",
    },
    {
        "pub_key": b"c4ed8d7b867e15f726b49879e3ac91d21bc8c3c05c06d6df74db0b64ae2855ad",
        "address_dec": b"c4ed8d7b867e15f726b49879e3ac91d21bc8c3c05c06d6df74db0b64ae2855ad"
                       b"00374080e081547ef57915b88c631b3c7359dd6abfda1da8045f4bd336b30e03",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"00374080e081547ef57915b88c631b3c7359dd6abfda1da8045f4bd336b30e03"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
        },
        "address": "495wjBmEpuiiLgDdUWfhBEc9KKsZbDCfoeNoqvUru1gpVwKqvTJgCEoNEfHn9sgxyxB7Str2eEDfSV6yciUAXZWV1RF5Vkx",
    },
    {
        "pub_key": b"b70bc5d0968175c398c5240c9ae26db7ca07026c5c507fd3bb415bdf2d2061d9",
        "address_dec": b"b70bc5d0968175c398c5240c9ae26db7ca07026c5c507fd3bb415bdf2d2061d9"
                       b"dd891739a743d9fe51bee4f33d153822541b2fd6c1b549a1caa5dfa3fcd2852c",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"dd891739a743d9fe51bee4f33d153822541b2fd6c1b549a1caa5dfa3fcd2852c"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
        },
        "address": "48ZS3pssZWLZiXwvaiqXQGXjz96yqQAnrcR4WLnxqaQxdSZtV1VvSDNjYDXX12ith56k2jNmsdMzGU4ahuaqjBJL64SfaZ5",
    },
    {
        "pub_key": b"4ec7bbf3a7066c46e58305954b9d8982ac973e0df927d422e830b8f2fbc2bafc",
        "address_dec": b"4ec7bbf3a7066c46e58305954b9d8982ac973e0df927d422e830b8f2fbc2bafc"
                       b"1bcda142d33bdc115f6b20e882891f904511b0ebada36a0296c0cd3b4e9e081a",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"1bcda142d33bdc115f6b20e882891f904511b0ebada36a0296c0cd3b4e9e081a"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
        },
        "address": "44cGCCdMcuyCrnYG2UrZpkNrhnmsGawLP6qeDDajCCAmjAmcszA8aXd3uYAEXRsZbUR8bfyFgJfAq1S7h7ivfxNj3wcge5p",
    },
    {
        "pub_key": b"429ce905e595394f7b3fe9d4d556c794810c7661a55fd14c5fbfb0af759608f2",
        "address_dec": b"429ce905e595394f7b3fe9d4d556c794810c7661a55fd14c5fbfb0af759608f2"
                       b"1403d780b7d2e5493cfc5fe03ec6f60c83ccc91fd0c72075379b934d119c4bef",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"1403d780b7d2e5493cfc5fe03ec6f60c83ccc91fd0c72075379b934d119c4bef"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
        },
        "address": "449X6uL5cbAEJ532nkrBRxRqgCFgozQeCDmvaAVASdw5hVTmtiTEaKeDFW9XJj3VTK36Qm6PCxGjyLc9vXh1YmKpU2gCTff",
    },
]

# Tests for integrated addresses
# Some random public keys
# Verified with: https://xmr.llcoins.net/addresstests.html
TEST_VECT_INTEGRATED = [
    {
        "pub_key": b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422",
        "address_dec": b"a95d2eb7e157f0a169df0a9c490dcd8e0feefb31bbf1328ca4938592a9d02422"
                       b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"dc2a1b478b8cc0ee655324fb8299c8904f121ab113e4216fbad6fe6d000758f5"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
            "payment_id": binascii.unhexlify(b"9a69fc3ca2eee2d9"),
        },
        "address": "4Hk2skWFnHVTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5i5fCBuJ3ufPRXhfuLD",
    },
    {
        "pub_key": b"c4ed8d7b867e15f726b49879e3ac91d21bc8c3c05c06d6df74db0b64ae2855ad",
        "address_dec": b"c4ed8d7b867e15f726b49879e3ac91d21bc8c3c05c06d6df74db0b64ae2855ad"
                       b"00374080e081547ef57915b88c631b3c7359dd6abfda1da8045f4bd336b30e03",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"00374080e081547ef57915b88c631b3c7359dd6abfda1da8045f4bd336b30e03"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
            "payment_id": binascii.unhexlify(b"2ffdf6f57391f583"),
        },
        "address": "4JncjzajSBEiLgDdUWfhBEc9KKsZbDCfoeNoqvUru1gpVwKqvTJgCEoNEfHn9sgxyxB7Str2eEDfSV6yciUAXZWV1XvW6QyZKDNFqHokyf",
    },
    {
        "pub_key": b"b70bc5d0968175c398c5240c9ae26db7ca07026c5c507fd3bb415bdf2d2061d9",
        "address_dec": b"b70bc5d0968175c398c5240c9ae26db7ca07026c5c507fd3bb415bdf2d2061d9"
                       b"dd891739a743d9fe51bee4f33d153822541b2fd6c1b549a1caa5dfa3fcd2852c",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"dd891739a743d9fe51bee4f33d153822541b2fd6c1b549a1caa5dfa3fcd2852c"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
            "payment_id": binascii.unhexlify(b"53b0af55057f82d6"),
        },
        "address": "4JG74dhNAmrZiXwvaiqXQGXjz96yqQAnrcR4WLnxqaQxdSZtV1VvSDNjYDXX12ith56k2jNmsdMzGU4ahuaqjBJL8R2YUpjySTTRDZtJUh",
    },
    {
        "pub_key": b"4ec7bbf3a7066c46e58305954b9d8982ac973e0df927d422e830b8f2fbc2bafc",
        "address_dec": b"4ec7bbf3a7066c46e58305954b9d8982ac973e0df927d422e830b8f2fbc2bafc"
                       b"1bcda142d33bdc115f6b20e882891f904511b0ebada36a0296c0cd3b4e9e081a",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"1bcda142d33bdc115f6b20e882891f904511b0ebada36a0296c0cd3b4e9e081a"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
            "payment_id": binascii.unhexlify(b"e95d162eef6927c2"),
        },
        "address": "4EJwD1SrEBVCrnYG2UrZpkNrhnmsGawLP6qeDDajCCAmjAmcszA8aXd3uYAEXRsZbUR8bfyFgJfAq1S7h7ivfxNj5W5QgLPoBzeNyLeTLy",
    },
    {
        "pub_key": b"429ce905e595394f7b3fe9d4d556c794810c7661a55fd14c5fbfb0af759608f2",
        "address_dec": b"429ce905e595394f7b3fe9d4d556c794810c7661a55fd14c5fbfb0af759608f2"
                       b"1403d780b7d2e5493cfc5fe03ec6f60c83ccc91fd0c72075379b934d119c4bef",
        "address_params": {
            "pub_vkey": binascii.unhexlify(b"1403d780b7d2e5493cfc5fe03ec6f60c83ccc91fd0c72075379b934d119c4bef"),
            "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
            "payment_id": binascii.unhexlify(b"f3a86129cd2f93e6"),
        },
        "address": "4DrC7i9aDrgEJ532nkrBRxRqgCFgozQeCDmvaAVASdw5hVTmtiTEaKeDFW9XJj3VTK36Qm6PCxGjyLc9vXh1YmKph8qJwcHBaeWT21kw6w",
    },
]

# Tests for decoding with invalid strings
TEST_VECT_DEC_INVALID = [
    # Invalid net version
    "4Hk2skWFnHVTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5UfNPmhK",
    # Invalid checksum
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5Uh988pj",
    # Invalid public key
    "49bLMVdRMSJfxBsdwA9mPRYgLCSmjvCbgHMxui5r4jmj1LQpYRHLDVMNEfHn9sgxyxB7Str2eEDfSV6yciUAXZWV1PC7Fsy",
    # Invalid length
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6iSREtrBwCRHwyghuaDa9mEE5w3MaRdaNYFaf7oNC6Nx4w88CT",
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5371Afo7UQ",
]

# Tests for decoding with invalid strings (integrated address)
TEST_VECT_DEC_INTEGRATED_INVALID = [
    # Invalid net version
    "4Hk2skWFnHVTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5hzTK5VQYYqE31cQRUa",
    # Invalid checksum
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5hzTK5VQYYqE2z57M7S",
    # Invalid payment ID
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5hzTK5VQYYqE2rBcifL",
    # Invalid public key
    "49bLMVdRMSJfxBsdwA9mPRYgLCSmjvCbgHMxui5r4jmj1LQpYRHLDVMNEfHn9sgxyxB7Str2eEDfSV6yciUAXZWV1W723RTUpoZ12J1aPt",
    # Invalid length
    "4Hk2skWFnHVTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6iSREtrBwCRHwyghuaDa9mEE5w3MaRdaNYFaf7oNC6Nx3rZwuSi5uqJ1s3oNf",
    "483MrwgmB1yTzuzmJPSiWGQmBYC1Z21yTQXQuDWv4MZm6qBnA4CCMXVgsjoFRmGkATR8yeytc2tFJKgvKz1Bbhj5hyowuhFVyDz19VwS3hUs",
]


#
# Tests
#
class XmrAddrTests(AddrBaseTests):
    # Test encode key
    def test_encode_key(self):
        self._test_encode_key(XmrAddrEncoder, Ed25519MoneroPublicKey, TEST_VECT)
        self._test_encode_key(XmrIntegratedAddrEncoder, Ed25519MoneroPublicKey, TEST_VECT_INTEGRATED)

    # Test decode address
    def test_decode_addr(self):
        self._test_decode_addr(XmrAddrDecoder, TEST_VECT)
        self._test_decode_addr(XmrIntegratedAddrDecoder, TEST_VECT_INTEGRATED)

    # Test invalid decoding
    def test_invalid_dec(self):
        self._test_invalid_dec(
            XmrAddrDecoder,
            {
                "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
            },
            TEST_VECT_DEC_INVALID
        )
        self._test_invalid_dec(
            XmrIntegratedAddrDecoder,
            {
                "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_net_ver"),
                "payment_id": binascii.unhexlify(b"1111111111111111"),
            },
            TEST_VECT_DEC_INTEGRATED_INVALID
        )

    # Test invalid keys
    def test_invalid_keys(self):
        self._test_invalid_keys(
            XmrAddrEncoder,
            {
                "pub_vkey": TEST_ED25519_MONERO_PUB_KEY,
                "net_ver": b"",
            },
            TEST_ED25519_MONERO_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )
        self._test_invalid_keys(
            XmrIntegratedAddrEncoder,
            {
                "pub_vkey": TEST_ED25519_MONERO_PUB_KEY,
                "net_ver": b"",
                "payment_id": b"\x00" * XmrAddrConst.PAYMENT_ID_BYTE_LEN,
            },
            TEST_ED25519_MONERO_ADDR_INVALID_KEY_TYPES,
            TEST_VECT_ED25519_PUB_KEY_INVALID
        )

    # Test invalid parameters
    def test_invalid_params(self):
        self._test_invalid_params_dec(
            XmrIntegratedAddrDecoder,
            {
                "net_ver": CoinsConf.MoneroMainNet.ParamByKey("addr_int_net_ver"),
                "payment_id": None,
            },
            ValueError
        )
        self._test_invalid_params_enc(
            XmrIntegratedAddrEncoder,
            {
                "pub_vkey": TEST_ED25519_MONERO_PUB_KEY,
                "net_ver": b"",
                "payment_id": b"\x00" * (XmrAddrConst.PAYMENT_ID_BYTE_LEN - 1),
            },
            ValueError)
        self._test_invalid_params_enc(
            XmrIntegratedAddrEncoder,
            {
                "pub_vkey": TEST_ED25519_MONERO_PUB_KEY,
                "net_ver": b"",
                "payment_id": b"\x00" * (XmrAddrConst.PAYMENT_ID_BYTE_LEN + 1),
            },
            ValueError
        )

    # Test old address class
    def test_old_addr_cls(self):
        self.assertTrue(XmrAddr is XmrAddrEncoder)
        self.assertTrue(XmrIntegratedAddr is XmrIntegratedAddrEncoder)
