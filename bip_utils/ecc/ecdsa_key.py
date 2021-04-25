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
import ecdsa
from ecdsa.curves import SECP256k1
from bip_utils.ecc.key_bytes import KeyBytes


class EcdsaPublicKey:
    """ ECDSA public key class. """

    #@staticmethod
    #def FromString(data_str: str) -> EcdsaPublicKey:
    #    return EcdsaPublicKey(ecdsa.VerifyingKey.from_string(data_str, curve=SECP256k1))

    def __init__(self,
                 ecdsa_obj: ecdsa.VerifyingKey) -> None:
        """ Construct class.

        Args:
            ecdsa_obj (ecdsa.VerifyingKey): ecdsa.VerifyingKey object
        """
        self.m_ecdsa_obj = ecdsa_obj

    def RawCompressed(self) -> KeyBytes:
        """ Return raw compressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_ecdsa_obj.to_string("compressed"))

    def RawUncompressed(self) -> KeyBytes:
        """ Return raw uncompressed public key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_ecdsa_obj.to_string("uncompressed"))


class EcdsaPrivateKey:
    """ ECDSA private key class. """

    def __init__(self,
                 ecdsa_obj: ecdsa.SigningKey) -> None:
        """ Construct class.

        Args:
            ecdsa_obj (ecdsa.SigningKey): ecdsa.SigningKey object
        """
        self.m_ecdsa_obj = ecdsa_obj

    def Raw(self) -> KeyBytes:
        """ Return raw private key.

        Returns:
            KeyBytes object: KeyBytes object
        """
        return KeyBytes(self.m_ecdsa_obj.to_string())
