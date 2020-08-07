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
from bip_utils.utils import ConvUtils


class CoinNames:
    """ Helper class for representing coin names. """

    def __init__(self, name, abbr):
        """ Construct class.

        Args:
            name (str): Name
            abbr (str): Abbreviation
        """
        self.m_name = name
        self.m_abbr = abbr

    def Name(self):
        """ Get name.

        Returns :
            str: Name
        """
        return self.m_name

    def Abbreviation(self):
        """ Get abbreviation.

        Returns:
            str: Abbreviation
        """
        return self.m_abbr


class KeyNetVersions:
    """ Helper class for representing key net versions. """

    def __init__(self, pub_net_ver, priv_net_ver):
        """ Construct class.

        Args:
            pub_net_ver (bytes) : Public net version
            priv_net_ver (bytes): Private net version
        """
        self.m_pub_net_ver  = ConvUtils.HexStringToBytes(pub_net_ver)
        self.m_priv_net_ver = ConvUtils.HexStringToBytes(priv_net_ver)

    def Public(self):
        """ Get public net version.

        Returns:
            bytes: Public net version
        """
        return self.m_pub_net_ver

    def Private(self):
        """ Get private net version.

        Returns:
            bytes: Private net version
        """
        return self.m_priv_net_ver


class NetVersions:
    """ Helper class for representing net versions. """

    def __init__(self, main_net_ver = None, test_net_ver = None):
        """ Construct class.

        Args:
            main_net_ver (object): Main net version, None by default
            test_net_ver (object): Test net verions, None by default
        """
        self.m_main_net_ver = main_net_ver
        self.m_test_net_ver = test_net_ver

    def Main(self):
        """ Get main net version.

        Returns:
            object: Main net version
        """
        return self.m_main_net_ver

    def Test(self):
        """ Get test net version.

        Returns:
            object: Test net version
        """
        return self.m_test_net_ver
