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
import sha3


class EthAddrConst:
    """ Class container for Ethereum address constants. """

    # Prefix
    PREFIX     = "0x"
    # Start byte
    START_BYTE = 24


class EthAddrUtils:
    """ Class container for Ethereum address utility functions. """

    def ChecksumEncode(addr):
        """ Checksum encode the specified address.

        Args:
            addr (str) : address string

        Returns (str):
            Checksum encoded address
        """

        enc_addr = ""

        # Compute address digest
        addr_digest = sha3.keccak_256(addr.encode()).hexdigest()
        # Encode it
        for i, c in enumerate(addr):
            enc_addr += c.upper() if (int(addr_digest[i], 16) >= 8) else c.lower()

        return enc_addr


class EthAddr:
    """ Ethereum address class. It allows the Ethereum address generation. """

    @staticmethod
    def ToAddress(pub_key_bytes):
        """ Get address in Ethereum format.

        Args:
            pub_key_bytes (bytes) : public key bytes

        Returns (str):
            Address string
        """
        addr = sha3.keccak_256(pub_key_bytes).hexdigest()[EthAddrConst.START_BYTE:]
        return EthAddrConst.PREFIX + EthAddrUtils.ChecksumEncode(addr)
