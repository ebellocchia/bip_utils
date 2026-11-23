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
Module for SLIP39 seed generation.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from typing import Sequence, Union

from bip_utils.slip.slip39.slip39_master_secret_encrypter import Slip39MasterSecretEncrypter
from bip_utils.slip.slip39.slip39_shares_combiner import Slip39EncryptedMasterSecret, Slip39SharesCombiner
from bip_utils.utils.mnemonic import Mnemonic


class Slip39SeedGenerator:
    """
    SLIP39 seed generator class.
    It combines share mnemonics to recover the master secret, which is the BIP32 seed.
    """

    m_enc_master_secret: Slip39EncryptedMasterSecret

    def __init__(self,
                 mnemonics: Union[str, Mnemonic, Sequence[Union[str, Mnemonic]]]) -> None:
        """
        Construct class.
        The shares are validated and combined, so that only the passphrase is needed to get the seed.
        Duplicated shares are ignored.

        Args:
            mnemonics (str, Mnemonic object or list): Share mnemonic(s)

        Raises:
            MnemonicChecksumError: If the checksum of a mnemonic is not valid
            ValueError: If a mnemonic is not valid or the shares cannot be combined
        """
        self.m_enc_master_secret = Slip39SharesCombiner.Combine(mnemonics)

    def Generate(self,
                 passphrase: str = "") -> bytes:
        """
        Generate the seed (i.e. decrypt the master secret) using the specified passphrase.
        Any passphrase results in a valid seed, since there is no way to verify it.

        Args:
            passphrase (str, optional): Passphrase, only printable ASCII characters (default: empty)

        Returns:
            bytes: Generated seed

        Raises:
            ValueError: If the passphrase is not valid
        """
        return Slip39MasterSecretEncrypter.Decrypt(self.m_enc_master_secret.value,
                                                   passphrase,
                                                   self.m_enc_master_secret.iteration_exponent,
                                                   self.m_enc_master_secret.identifier,
                                                   self.m_enc_master_secret.extendable)
