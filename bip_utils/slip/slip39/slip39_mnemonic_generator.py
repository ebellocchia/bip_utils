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
Module for SLIP39 mnemonic generation.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
import dataclasses
import os
import secrets
from typing import List, Sequence, Tuple, Union

from bip_utils.slip.slip39.slip39_master_secret_encrypter import Slip39MasterSecretEncrypter
from bip_utils.slip.slip39.slip39_mnemonic import Slip39MnemonicConst, Slip39WordsNum
from bip_utils.slip.slip39.slip39_mnemonic_encoder import Slip39MnemonicEncoder
from bip_utils.slip.slip39.slip39_shamir import Slip39Shamir
from bip_utils.slip.slip39.slip39_share import Slip39Share
from bip_utils.slip.slip39.slip39_shares_combiner import Slip39EncryptedMasterSecret, Slip39SharesCombiner
from bip_utils.utils.mnemonic import Mnemonic


class Slip39MnemonicGenerator:
    """
    SLIP39 mnemonic generator class.
    It splits a master secret into share mnemonics, in according to the specified two-level scheme: the master secret
    is split into groups, any group_threshold of them are needed to recover it, and each group is split into members.
    """

    m_group_threshold: int
    m_groups: List[Tuple[int, int]]
    m_extendable: bool
    m_iteration_exponent: int
    m_encoder: Slip39MnemonicEncoder

    def __init__(self,
                 group_threshold: int = 1,
                 groups: Sequence[Tuple[int, int]] = ((1, 1),),
                 extendable: bool = True,
                 iteration_exponent: int = 1) -> None:
        """
        Construct class.
        The default parameters generate a single share (1-of-1 scheme).

        Args:
            group_threshold (int, optional)          : Number of groups needed to recover the master secret
                                                       (default: 1)
            groups (list[tuple[int, int]], optional) : (member threshold, member count) for each group
                                                       (default: a single 1-of-1 group)
            extendable (bool, optional)              : Extendable backup flag (default: true)
            iteration_exponent (int, optional)       : Iteration exponent, PBKDF2 iterations are 10000 * 2^exponent
                                                       (default: 1)

        Raises:
            ValueError: If the parameters are not valid
        """
        max_shares_num = Slip39MnemonicConst.MAX_SHARES_NUM
        if not 1 <= len(groups) <= max_shares_num:
            raise ValueError(f"Invalid number of groups ({len(groups)})")
        if not 1 <= group_threshold <= len(groups):
            raise ValueError(f"Invalid group threshold ({group_threshold})")
        for member_threshold, member_count in groups:
            if not 1 <= member_threshold <= member_count <= max_shares_num:
                raise ValueError(f"Invalid member threshold ({member_threshold}) or count ({member_count})")
            # Shares of a group with threshold 1 would only differ in the member index, see SLIP39
            if member_threshold == 1 and member_count > 1:
                raise ValueError("Groups with member threshold 1 shall have a single member")
        if not 0 <= iteration_exponent < 2 ** Slip39MnemonicConst.ITER_EXP_BIT_LEN:
            raise ValueError(f"Invalid iteration exponent ({iteration_exponent})")

        self.m_group_threshold = group_threshold
        self.m_groups = list(groups)
        self.m_extendable = extendable
        self.m_iteration_exponent = iteration_exponent
        self.m_encoder = Slip39MnemonicEncoder()

    def FromWordsNumber(self,
                        words_num: Union[int, Slip39WordsNum],
                        passphrase: str = "") -> List[List[Mnemonic]]:
        """
        Generate share mnemonics with the specified words number from a random master secret.

        Args:
            words_num (int or Slip39WordsNum): Words number (20 for a 128-bit, 33 for a 256-bit master secret)
            passphrase (str, optional)       : Passphrase (default: empty)

        Returns:
            list[list[Mnemonic]]: Share mnemonics, one list for each group

        Raises:
            ValueError: If words number or passphrase are not valid
        """
        if words_num not in Slip39MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        secret_byte_len = Slip39MnemonicConst.WORDS_NUM_TO_SECRET_BYTE_LEN[Slip39WordsNum(words_num)]
        return self.FromMasterSecret(os.urandom(secret_byte_len), passphrase)

    def FromMasterSecret(self,
                         master_secret: bytes,
                         passphrase: str = "") -> List[List[Mnemonic]]:
        """
        Generate share mnemonics from the specified master secret.
        For BIP32 wallets, the master secret is the BIP32 seed.

        Args:
            master_secret (bytes)     : Master secret (at least 16 bytes, with an even length)
            passphrase (str, optional): Passphrase, only printable ASCII characters (default: empty)

        Returns:
            list[list[Mnemonic]]: Share mnemonics, one list for each group

        Raises:
            ValueError: If master secret or passphrase are not valid
        """
        if len(master_secret) < Slip39MnemonicConst.MIN_SECRET_BYTE_LEN or len(master_secret) % 2 != 0:
            raise ValueError(f"Invalid master secret length ({len(master_secret)})")

        identifier = secrets.randbits(Slip39MnemonicConst.ID_BIT_LEN)
        return self.__SplitEncMasterSecret(
            Slip39EncryptedMasterSecret(
                identifier=identifier,
                extendable=self.m_extendable,
                iteration_exponent=self.m_iteration_exponent,
                value=Slip39MasterSecretEncrypter.Encrypt(master_secret,
                                                          passphrase,
                                                          self.m_iteration_exponent,
                                                          identifier,
                                                          self.m_extendable),
            )
        )

    def FromMnemonics(self,
                      mnemonics: Union[str, Mnemonic, Sequence[Union[str, Mnemonic]]]) -> List[List[Mnemonic]]:
        """
        Generate a new set of share mnemonics from existing ones (backup extension), with the scheme of the class.
        The encrypted master secret is split again with a new random identifier, so the new shares result in the same
        seed for any passphrase and the passphrase is not needed. Shares of the two sets cannot be mixed.
        The extendable flag and iteration exponent are kept from the existing shares, so the ones specified when
        constructing the class are ignored.
        The existing shares remain valid.

        Args:
            mnemonics (str, Mnemonic object or list): Existing share mnemonic(s), enough to recover the master secret

        Returns:
            list[list[Mnemonic]]: Share mnemonics, one list for each group

        Raises:
            MnemonicChecksumError: If the checksum of a mnemonic is not valid
            ValueError: If a mnemonic is not valid, the shares cannot be combined or they are not extendable
        """
        enc_master_secret = Slip39SharesCombiner.Combine(mnemonics)
        # Without the extendable flag, the identifier is used to encrypt the master secret.
        # A new identifier would change it and SLIP39 discourages to create another set with the same one.
        if not enc_master_secret.extendable:
            raise ValueError("Shares without the extendable backup flag cannot be extended")

        # Make sure the new set has a different identifier
        identifier = enc_master_secret.identifier
        while identifier == enc_master_secret.identifier:
            identifier = secrets.randbits(Slip39MnemonicConst.ID_BIT_LEN)

        return self.__SplitEncMasterSecret(dataclasses.replace(enc_master_secret, identifier=identifier))

    def __SplitEncMasterSecret(self,
                               enc_master_secret: Slip39EncryptedMasterSecret) -> List[List[Mnemonic]]:
        """
        Split the encrypted master secret into share mnemonics.

        Args:
            enc_master_secret (Slip39EncryptedMasterSecret object): Encrypted master secret

        Returns:
            list[list[Mnemonic]]: Share mnemonics, one list for each group
        """
        group_shares = Slip39Shamir.SplitSecret(self.m_group_threshold, len(self.m_groups), enc_master_secret.value)
        return [
            [
                self.m_encoder.Encode(
                    Slip39Share(
                        identifier=enc_master_secret.identifier,
                        extendable=enc_master_secret.extendable,
                        iteration_exponent=enc_master_secret.iteration_exponent,
                        group_index=group_index,
                        group_threshold=self.m_group_threshold,
                        group_count=len(self.m_groups),
                        member_index=member_index,
                        member_threshold=member_threshold,
                        value=member_value,
                    )
                )
                for member_index, member_value in Slip39Shamir.SplitSecret(member_threshold,
                                                                           member_count,
                                                                           group_value)
            ]
            for (group_index, group_value), (member_threshold, member_count) in zip(group_shares, self.m_groups)
        ]
