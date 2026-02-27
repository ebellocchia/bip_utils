# Copyright (c) 2026 Emanuele Bellocchia
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

"""
Module for TON mnemonic seed generation.
Reference: https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.ts
"""

# Imports
from enum import Enum, auto, unique
from typing import Union

from bip_utils.ton.mnemonic.ton_mnemonic import TonLanguages
from bip_utils.ton.mnemonic.ton_mnemonic_validator import TonMnemonicValidator
from bip_utils.ton.mnemonic.ton_seed_utils import TonSeedUtils
from bip_utils.utils.mnemonic import Mnemonic


@unique
class TonSeedTypes(Enum):
    """Enumerative for TON seed types."""

    HD_KEY = auto()
    PRIVATE_KEY = auto()


class TonSeedGenerator:
    """
    TON seed generator class.
    It generates the seed from a mnemonic.
    """

    m_mnemonic: str
    m_passphrase: str

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 passphrase: str = "",
                 lang: TonLanguages = TonLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object): Mnemonic
            passphrase (str, optional)        : Passphrase (empty by default)
            lang (TonLanguages, optional)    : Language (default: English)

        Raises:
            ValueError: If the mnemonic is not valid
        """
        mnemonic_str = mnemonic if isinstance(mnemonic, str) else mnemonic.ToStr()
        if not TonMnemonicValidator(lang).IsValid(mnemonic_str, passphrase):
            raise ValueError(f"Invalid mnemonic {mnemonic_str}")
        self.m_mnemonic = mnemonic_str
        self.m_passphrase = passphrase

    def Generate(self,
                 seed_type: TonSeedTypes = TonSeedTypes.PRIVATE_KEY) -> bytes:
        """
        Generate seed.

        Args:
            seed_type (TonSeedTypes, optional): Seed type (PRIVATE_KEY by default)

        Returns:
            bytes: Generated seed

        Raises:
            TypeError: If the seed type is not a TonSeedTypes enum
        """
        if not isinstance(seed_type, TonSeedTypes):
            raise TypeError("Seed type is not an enumerative of TonSeedTypes")

        entropy_bytes = TonSeedUtils.GetEntropyBytes(self.m_mnemonic, self.m_passphrase)
        if seed_type == TonSeedTypes.PRIVATE_KEY:
            return TonSeedUtils.GetPrivateKeySeed(entropy_bytes)
        return TonSeedUtils.GetHdKeySeed(entropy_bytes)
