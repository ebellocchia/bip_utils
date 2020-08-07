# Copyright (c) 2014 Corgan Labs, 2020 Emanuele Bellocchia
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


# Import
from bip_utils.bip.bip32_utils import Bip32Utils


class Bip32PathParserConst:
    """ Class container for path parser constants. """

    # Hardened characters
    HARDENED_CHARS = ("'", "p")
    # Master character
    MASTER_CHAR    = "m"


class Bip32PathParser:
    """ Path parser class. It parses a BIP-0032 path and return a list of its indexes. """

    @staticmethod
    def Parse(path, skip_master = False):
        """ Validate a path.

        Args:
            path (str)                  : Path
            skip_master (bool, optional): True to skip the master in path (e.g. 0/1/2), false otherwise (e.g. m/0/1/2)

        Returns:
            list: List with path indexes
        """

        return Bip32PathParser.__ParseElems(path.split("/"), skip_master)

    @staticmethod
    def __ParseElems(path_elems, skip_master):
        """ Parse path elements.

        Args:
            path_elems (list)           : Path element list
            skip_master (bool, optional): True to skip the master in path (e.g. 0/1/2), false otherwise (e.g. m/0/1/2)

        Returns:
            list: List with path indexes
        """

        path_list = []

        # Check each element
        for i in range(len(path_elems)):
            path_elem = path_elems[i].strip()

            # Skip last empty element if any
            if len(path_elem) == 0 and i == len(path_elems) - 1:
                continue

            # If path starts from master, the first element shall be "m"
            if i == 0 and not skip_master:
                if path_elem != Bip32PathParserConst.MASTER_CHAR:
                    return []
                path_list.append(Bip32PathParserConst.MASTER_CHAR)
            else:
                # Get index
                path_idx = Bip32PathParser.__GetElemIndex(path_elem)
                # Check it
                if path_idx is None:
                    return []
                # Add it to the list
                path_list.append(path_idx)

        return path_list

    @staticmethod
    def __GetElemIndex(path_elem):
        """ Get index of a path element.

        Args:
            path_elem (str): Path element

        Returns:
            int: Index of the element
            None: If the element is not a valid index
        """

        # Get if hardened
        is_hardened = len(path_elem) > 0  and path_elem[-1] in Bip32PathParserConst.HARDENED_CHARS

        # If hardened, remove the last character from the string
        if is_hardened:
            path_elem = path_elem[:-1]

        # The remaining string shall be numeric
        if not path_elem.isnumeric():
            return None

        return int(path_elem) if not is_hardened else Bip32Utils.HardenIndex(int(path_elem))
