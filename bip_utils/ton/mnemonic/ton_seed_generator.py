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

"""Module for Algorand mnemonic seed generation."""

# Imports
from symtable import Class
from typing import Optional, Union

from bip_utils.utils.mnemonic import Mnemonic
from bip_utils.utils.crypto.hmac import HmacSha512
from bip_utils.utils.crypto.pbkdf2 import Pbkdf2HmacSha512


class TonSeedGenerator:
    """
    TON seed generator class.
    It generates the seed from a mnemonic.
    """

    m_entropy_bytes: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 ) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object) : Mnemonic

        Raises:
            ValueError: If the mnemonic is not valid
        """
        self.mnemonic = mnemonic if isinstance(mnemonic, str) else mnemonic.ToStr()
      


    def Generate(self, passphrase: Optional[str] = "") -> bytes:
        """
        Generate seed. The seed is the PBKDF2-HMAC-SHA512 of the entropy bytes.
        See https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts

        Returns:
            bytes: Generated seed
        """
        self.entropy_bytes = HmacSha512().QuickDigest(self.mnemonic, passphrase)    

        seed = Pbkdf2HmacSha512().DeriveKey(self.entropy_bytes, "TON default seed",   100000, 64)

        return seed

    