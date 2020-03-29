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
import hashlib
import hmac


def Sha256(data_bytes):
    """ Compute the SHA256 of the specified bytes.

    Args:
        data_bytes (bytes) : data bytes

    Returns (bytes):
        Computed SHA256
    """
    return hashlib.sha256(data_bytes).digest()


def Sha256DigestSize():
    """ Get the SHA256 digest size in bytes.

    Returns (int):
        SHA256 digest size in bytes
    """
    return hashlib.sha256().digest_size


def HmacSha512(key_bytes, data_bytes):
    """ Compute the HMAC-SHA512 of the specified bytes with the specified key.

    Args:
        key_bytes (bytes) : key bytes
        data_bytes (bytes) : data bytes

    Returns (int):
        Computed HMAC-SHA512
    """
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()


def Hash160(data_bytes):
    """ Compute the Bitcoin Hash-160 of the specified bytes.

    Args:
        data_bytes (bytes) : data bytes

    Returns (int):
        Computed Hash-160
    """
    return hashlib.new("ripemd160", hashlib.sha256(data_bytes).digest()).digest()


def BytesToInteger(data_bytes):
    """ Convert the specified bytes to integer.

    Args:
        data_bytes (bytes) : data bytes

    Returns (int):
        Integer representation
    """
    return int(binascii.hexlify(data_bytes), 16)


def BytesToBinaryStr(data_bytes, zero_pad = 0):
    """ Convert the specified bytes to a binary string.

    Args:
        data_bytes (bytes) : data bytes
        zero_pad (int, optional) : zero padding, 0 if not specified

    Returns (str):
        Binary string
    """
    return IntToBinaryStr(BytesToInteger(data_bytes), zero_pad)


def IntToBinaryStr(data_int, zero_pad = 0):
    """ Convert the specified integer to a binary string.

    Args:
        data_int (int) : data integer
        zero_pad (int, optional) : zero padding, 0 if not specified

    Returns (str):
        Binary string
    """
    return bin(data_int)[2:].zfill(zero_pad)


def BytesFromBinaryStr(data_str, zero_pad = 0):
    """ Convert the specified binary string to bytes.

    Args:
        data_str (str) : data string
        zero_pad (int, optional) : zero padding, 0 if not specified

    Returns (bytes):
        Bytes representation
    """
    return binascii.unhexlify(hex(int(data_str, 2))[2:].zfill(zero_pad))


def ListToBytes(data_list):
    """ Convert the specified list to bytes

    Args:
        data_list (list) : data bytes

    Returns (bytes):
        Correspondent bytes representation
    """
    return bytes(bytearray(data_list))
