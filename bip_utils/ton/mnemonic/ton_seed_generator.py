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

"""Module for TON mnemonic seed generation."""

# Imports
from typing import Optional, Union

from bip_utils.utils.crypto.hmac import HmacSha512
from bip_utils.utils.crypto.pbkdf2 import Pbkdf2HmacSha512
from bip_utils.utils.mnemonic import Mnemonic


class TonSeedGeneratorConst:
    """Class container for TON seed generator constants."""

    # Salt modifier for seed generation
    SEED_SALT_MOD: str = "TON default seed"
    # Seed length in bytes
    SEED_LEN_BYTES: int = 64
    # PBKDF2 round for seed generation
    SEED_PBKDF2_ROUNDS: int = 100000


class TonSeedGenerator:
    """
    TON seed generator class.
    It generates the seed from a mnemonic.
    """

    m_mnemonic: Union[str, Mnemonic]

    def __init__(self,
                 mnemonic: Union[str, Mnemonic]) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object) : Mnemonic

        Raises:
            ValueError: If the mnemonic is not valid
        """
        self.m_mnemonic = mnemonic if isinstance(mnemonic, str) else mnemonic.ToStr()

    def Generate(self,
                 passphrase: Optional[str] = "") -> bytes:
        """
        Generate seed. The seed is the PBKDF2-HMAC-SHA512 of the entropy bytes.
        See https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts

        Args:
            passphrase (str, optional): Passphrase (empty by default)

        Returns:
            bytes: Generated seed
        """
        entropy_bytes = HmacSha512().QuickDigest(self.m_mnemonic, passphrase)
        return Pbkdf2HmacSha512().DeriveKey(entropy_bytes,
                                            TonSeedGeneratorConst.SEED_SALT_MOD,
                                            TonSeedGeneratorConst.SEED_PBKDF2_ROUNDS,
                                            TonSeedGeneratorConst.SEED_LEN_BYTES)
