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
from bisect import bisect_left


class AlgoUtils:
    """ Class container for algorithm utility functions. """

    @staticmethod
    def BinarySearch(arr, elem):
        """ Binary search algorithm simply implemented by using the bisect library.

        Args:
            arr (list): list of elements
            elem (any): element to be searched

        Returns:
            int: First index of the element, -1 if not found
        """

        INVALID_IDX = -1

        i = bisect_left(arr, elem)
        if i != len(arr) and arr[i] == elem:
            return i
        else:
            return INVALID_IDX

    @staticmethod
    def StringEncode(data_str, encoding = "utf-8"):
        """ Encode string to bytes.

        Args:
            data_str (str): Data string
            encoding (str): Encoding type

        Returns:
            bytes: String encoded to bytes
        """
        return data_str.encode(encoding)

    @staticmethod
    def IsStringMixed(data_str):
        """ Get if the specified string is in mixed case.

        Args:
            data_str (str): string

        Returns:
            bool: True if mixed case, false otherwise
        """
        return any(c.islower() for c in data_str) and any(c.isupper() for c in data_str)
