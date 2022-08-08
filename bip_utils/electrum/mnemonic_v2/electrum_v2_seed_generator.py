# Copyright (c) 2022 Emanuele Bellocchia
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

"""Module for Electrum v2 mnemonic seed generation."""

# Imports
from typing import Optional, Union

from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic import ElectrumV2Languages, ElectrumV2Mnemonic
from bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_validator import ElectrumV2MnemonicValidator
from bip_utils.utils.crypto import Pbkdf2HmacSha512
from bip_utils.utils.misc import StringUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumV2SeedGeneratorConst:
    """Class container for Electrum seed generator constants (v2)."""

    # Salt modifier for seed generation
    SEED_SALT_MOD: str = "electrum"
    # PBKDF2 round for seed generation
    SEED_PBKDF2_ROUNDS: int = 2048


class ElectrumV2SeedGenerator:
    """
    Electrum seed generator class (v2).
    It generates the seed from a mnemonic.
    """

    m_entropy_bytes: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 lang: Optional[ElectrumV2Languages] = None) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object)   : Mnemonic
            lang (ElectrumV2Languages, optional): Language, None for automatic detection

        Raises:
            ValueError: If the mnemonic is not valid
        """
        ElectrumV2MnemonicValidator(lang=lang).Validate(mnemonic)
        self.m_mnemonic = (ElectrumV2Mnemonic.FromString(mnemonic)
                           if isinstance(mnemonic, str)
                           else mnemonic)

    def Generate(self,
                 passphrase: str = "") -> bytes:
        """
        Generate the seed using the specified passphrase.

        Args:
            passphrase (str, optional): Passphrase, empty if not specified

        Returns:
            bytes: Generated seed
        """
        salt = StringUtils.NormalizeNfkd(ElectrumV2SeedGeneratorConst.SEED_SALT_MOD + passphrase)
        return Pbkdf2HmacSha512.DeriveKey(self.m_mnemonic.ToStr(),
                                          salt,
                                          ElectrumV2SeedGeneratorConst.SEED_PBKDF2_ROUNDS)
