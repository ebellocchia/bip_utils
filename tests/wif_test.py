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
from bip_utils import WifDecoder, WifEncoder


# Some keys randomly generated from:
# https://gobittest.appspot.com/PrivateKey
TEST_VECTOR = \
    [
        {
            "key_bytes" : b"5e9441950b3918772cc3da1fc6735b7c33f1bbe08a8f1e704be46cb664f7e457",
            "encode"    :  "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK2zNk",
        },
        {
            "key_bytes" : b"1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67",
            "encode"    :  "5HzxC8XHHAtoC5jVvScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
        },
        {
            "key_bytes" : b"3358a5243588f0746c2124bfd88897b19740d350e9490c6bbf28a494ab4440b9",
            "encode"    :  "5JCu9q9GHLHHFS1FqGtLfoGkztBx712cxk4ta6S1UizxLQS6eFp",
        },
        {
            "key_bytes" : b"7f42c14e4260bd7c8418dae971a0d91aacf9ec4a59005afca9ae79a09240b10c",
            "encode"    :  "5JnLHbJUuMcQNc9UC64SizxLYRw9Y2ecbiJW4f8U8htgYLDJVED",
        },
        {
            "key_bytes" : b"c8925812285db4a007562576251334aac2f92d740ab1c18085090c47e885e975",
            "encode"    :  "5KLcv3EqNcV4bjMHK3x9bxCd9brVhrDt5TbSk43HUfRij7NtZ9p",
        },
        {
            "key_bytes" : b"4dd5c47953169db14da8f2cbff14e6de5e9e48a0daec38e4988300eaba8ddd0e",
            "encode"    :  "5JQZmnApGh9pVQLBQXTk6CHoMrzVGcVRGR9NTZizLCQFm4AKa5t",
        },
        {
            "key_bytes" : b"6e6613bde60831b8f7e8da5403d1f8ed0e4f3a9b3d43a335fb177102d9ab8622",
            "encode"    :  "5JeuZxmhGsyweMdWMJpSbmdK24boSn7LX2rFNY5Kh4fnBJQByME",
        },
        {
            "key_bytes" : b"2932d10751d709703a202a047fb07c98f86e434d97fa972c08133e6bf17516a1",
            "encode"    :  "5J8RwayFGhJYqjGRzAYVeGj1vaykP1V2Zp6hWRM22PNFnyEdYSS",
        },
        {
            "key_bytes" : b"8d49f3cf2388f301b329a51c8c5f0451b2e84b95d7a0968ee73d072e6a804ce9",
            "encode"    :  "5JtWchFNvKBT25gZWeTmnc2NhhJCG8Hhexbn6FBzPkKM9Ljzh6e",
        },
        {
            "key_bytes" : b"ce2c0f4ebc9e74ad0393e6dfbe1dc9b270c1978927d219317d0d195a1852720f",
            "encode"    :  "5KP5yHk13cD5jcfqUCnCUTew9tPYANkwBHskM7TNsob5KMSXT4e",
        },
    ]

# Some WIF encoded strings with invalid checksum
TEST_VECTOR_CHK_ERR = \
    [
        "5JXwUhNu98kXkyhR8EpvpaTGRjj8JZEP7hWboB5xscgjbgK3zNk",
        "5HzxC8XHHAtoC5jVeScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
        "5JCu9q9GHLHHFS1FqGtLfoFkztBx712cxk4ta6S1UizxLQS6eFp",
    ]

# Some WIF encoded strings with invalid encoding
TEST_VECTOR_ENC_ERR = \
    [
        "5JnLHbJUuOcQNc9UC64SizlLYRw9Y2ecbiJW4f8U8htgYLDJVED",
        "5KL1v3EqNOV4bjMHK3x9bxCd9brVhrDt5TbSk43HUfRij7NtZ9p",
        "5JQZOnApGO9pVQLBQXTk6CHoMrzVGcVRGR9NTZizLCQFm4AKa5t",
    ]


#
# Tests
#
class Bech32Tests(unittest.TestCase):
    # Test decoder
    def test_decoder(self):
        for test in TEST_VECTOR:
            # Test decoder
            self.assertEqual(test["key_bytes"], binascii.hexlify(WifDecoder.Decode(test["encode"])))

    # Test encoder
    def test_encoder(self):
        for test in TEST_VECTOR:
            # Test encoder
            self.assertEqual(test["encode"], WifEncoder.Encode(binascii.unhexlify(test["key_bytes"])))

    # Test invalid checksum
    def test_invalid_checksum(self):
        for test in TEST_VECTOR_CHK_ERR:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(RuntimeError):
                WifDecoder.Decode(test)

    # Test invalid encoding
    def test_invalid_encoding(self):
        for test in TEST_VECTOR_ENC_ERR:
            # "with" is required because the exception is raised by Base58 module
            with self.assertRaises(ValueError):
                WifDecoder.Decode(test)

# Run test if executed
if __name__ == "__main__":
    unittest.main()
