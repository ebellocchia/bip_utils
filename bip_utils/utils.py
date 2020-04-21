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
from bisect import bisect_left


def Sha256(data_bytes):
    """ Compute the SHA256 of the specified bytes.

    Args:
        data_bytes (bytes): Data bytes

    Returns:
        bytes: Computed SHA256
    """
    return hashlib.sha256(data_bytes).digest()


def Sha256DigestSize():
    """ Get the SHA256 digest size in bytes.

    Returns:
        int: SHA256 digest size in bytes
    """
    return hashlib.sha256().digest_size


def HmacSha512(key_bytes, data_bytes):
    """ Compute the HMAC-SHA512 of the specified bytes with the specified key.

    Args:
        key_bytes (bytes) : Key bytes
        data_bytes (bytes): Data bytes

    Returns:
        bytes: Computed HMAC-SHA512
    """
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()


def Pbkdf2HmacSha512(password_bytes, salt_bytes, itr_num):
    """ Compute the PBKDF2 HMAC-SHA512 of the specified password, using the specified keys and iteration number.

    Args:
        password_bytes (bytes): Password bytes
        salt_bytes (bytes)    : Salt bytes
        itr_num (int)         : Iteration number

    Returns:
        bytes: Computed PBKDF2 HMAC-SHA512
    """
    return hashlib.pbkdf2_hmac("sha512", password_bytes, salt_bytes, itr_num)


def Hash160(data_bytes):
    """ Compute the Bitcoin Hash-160 of the specified bytes.

    Args:
        data_bytes (bytes): Data bytes

    Returns:
        bytes: Computed Hash-160
    """
    return hashlib.new("ripemd160", hashlib.sha256(data_bytes).digest()).digest()


def BytesToInteger(data_bytes):
    """ Convert the specified bytes to integer.

    Args:
        data_bytes (bytes): Data bytes

    Returns:
        int: Integer representation
    """
    return int(binascii.hexlify(data_bytes), 16)


def BytesToBinaryStr(data_bytes, zero_pad = 0):
    """ Convert the specified bytes to a binary string.

    Args:
        data_bytes (bytes)      : Data bytes
        zero_pad (int, optional): Zero padding, 0 if not specified

    Returns:
        str: Binary string
    """
    return IntToBinaryStr(BytesToInteger(data_bytes), zero_pad)


def IntToBinaryStr(data_int, zero_pad = 0):
    """ Convert the specified integer to a binary string.

    Args:
        data_int (int)          : Data integer
        zero_pad (int, optional): Zero padding, 0 if not specified

    Returns:
        str: Binary string
    """
    return bin(data_int)[2:].zfill(zero_pad)


def BytesFromBinaryStr(data_str, zero_pad = 0):
    """ Convert the specified binary string to bytes.

    Args:
        data_str (str)          : Data string
        zero_pad (int, optional): Zero padding, 0 if not specified

    Returns:
        bytes: Bytes representation
    """
    return binascii.unhexlify(hex(int(data_str, 2))[2:].zfill(zero_pad))


def ListToBytes(data_list):
    """ Convert the specified list to bytes

    Args:
        data_list (list): Data list

    Returns:
        bytes: Correspondent bytes representation
    """
    return bytes(bytearray(data_list))


def BytesToHexString(data_bytes, encoding = "utf-8"):
    """ Convert bytes to hex string.

    Args:
        data_bytes (str): Data bytes
        encoding (str)  : Encoding type

    Returns:
        str: Bytes converted to hex string
    """
    return binascii.hexlify(data_bytes).decode(encoding)


def HexStringToBytes(data_str):
    """ Convert hex string to bytes.

    Args:
        data_str (str): Data bytes

    Returns
        bytes: Hex string converted to bytes
    """
    return binascii.unhexlify(data_str)


def StringEncode(data_str, encoding = "utf-8"):
    """ Encode string to bytes.

    Args:
        data_str (str): Data string
        encoding (str): Encoding type

    Returns:
        bytes: String encoded to bytes
    """
    return data_str.encode(encoding)


def BinarySearch(arr, elem):
    """ Binary search algorithm simply implemented by using the bisect library.

    Args:
        arr (list): list of elements
        elem (any): element to be searched

    Returns:
        int: First index of the element, -1 if not found
    """
    i = bisect_left(arr, elem)
    if i != len(arr) and arr[i] == elem:
        return i
    else:
        return -1
