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
from abc import ABC, abstractmethod
from bip_utils.utils.conversion import ConvUtils


class KeyBytes:
    """ Key bytes class. It allows to get key bytes in different formats. """

    def __init__(self,
                 key_bytes: bytes) -> None:
        """ Construct class.

        Args:
            key_bytes (bytes): Key bytes
        """
        self.m_key_bytes = key_bytes

    def ToBytes(self) -> bytes:
        """ Get key bytes.

        Returns:
            bytes: Key bytes
        """
        return self.m_key_bytes

    def ToHex(self) -> str:
        """ Get key bytes in hex format.

        Returns:
            str: Key bytes in hex format
        """
        return ConvUtils.BytesToHexString(self.m_key_bytes)


class PublicKey(ABC):
    """ Public key interface. It allows to get a public key in different formats. """

    @abstractmethod
    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        pass

    @abstractmethod
    def ToAddress(self) -> str:
        """ Return address correspondent tot he public key.

        Returns:
            str: Address
        """
        pass


class PrivateKey(ABC):
    """ Private key interface. It allows to get a private key in different formats. """

    @abstractmethod
    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        pass

    @abstractmethod
    def ToExtended(self) -> str:
        """ Return key in serialized extended format.

        Returns:
            str: Key in serialized extended format
        """
        pass

    @abstractmethod
    def ToWif(self,
              compr_pub_key: bool) -> str:
        """ Return key in WIF format.

        Args:
            compr_pub_key (bool) : True if private key corresponds to a compressed public key, false otherwise

        Returns:
            str: Key in WIF format
        """
        pass
