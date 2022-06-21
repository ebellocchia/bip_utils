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

"""Module for Electrum mnemonic seed generation."""

# Imports
from typing import Union
from bip_utils.electrum.mnemonic.electrum_mnemonic import ElectrumLanguages, ElectrumMnemonic
from bip_utils.electrum.mnemonic.electrum_mnemonic_validator import ElectrumMnemonicValidator
from bip_utils.utils.misc import CryptoUtils, StringUtils
from bip_utils.utils.mnemonic import Mnemonic


class ElectrumSeedGeneratorConst:
    """Class container for Electrum seed generator constants."""

    # Salt modifier for seed generation
    SEED_SALT_MOD: str = "electrum"
    # PBKDF2 round for seed generation
    SEED_PBKDF2_ROUNDS: int = 2048
    # Seed length in bytes
    SEED_BYTE_LEN: int = 64


class ElectrumSeedGenerator:
    """
    Electrum seed generator class.
    It generates the seed from a mnemonic.
    """

    m_entropy_bytes: bytes

    def __init__(self,
                 mnemonic: Union[str, Mnemonic],
                 lang: ElectrumLanguages = ElectrumLanguages.ENGLISH) -> None:
        """
        Construct class.

        Args:
            mnemonic (str or Mnemonic object) : Mnemonic
            lang (ElectrumLanguages, optional): Language (default: English)

        Raises:
            ValueError: If the mnemonic is not valid
        """
        # Make sure that the given mnemonic is valid
        ElectrumMnemonicValidator(lang).Validate(mnemonic)

        self.m_mnemonic = (ElectrumMnemonic.FromString(mnemonic)
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
        salt = StringUtils.NormalizeNfkd(ElectrumSeedGeneratorConst.SEED_SALT_MOD + passphrase)
        return CryptoUtils.Pbkdf2HmacSha512(self.m_mnemonic.ToStr(),
                                            salt,
                                            ElectrumSeedGeneratorConst.SEED_PBKDF2_ROUNDS)
