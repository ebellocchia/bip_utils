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
Module for combining SLIP39 shares.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
"""

# Imports
from dataclasses import dataclass
from typing import Dict, List, Sequence, Union

from bip_utils.slip.slip39.slip39_mnemonic_decoder import Slip39MnemonicDecoder
from bip_utils.slip.slip39.slip39_shamir import Slip39Shamir
from bip_utils.slip.slip39.slip39_share import Slip39Share
from bip_utils.utils.mnemonic import Mnemonic


@dataclass(frozen=True)
class Slip39EncryptedMasterSecret:
    """Dataclass holding an encrypted master secret, with the parameters needed to decrypt it."""

    identifier: int
    extendable: bool
    iteration_exponent: int
    value: bytes


class Slip39SharesCombiner:
    """
    SLIP39 shares combiner class.
    It checks and combines share mnemonics to recover the encrypted master secret.
    """

    @classmethod
    def Combine(cls,
                mnemonics: Union[str, Mnemonic, Sequence[Union[str, Mnemonic]]]) -> Slip39EncryptedMasterSecret:
        """
        Combine share mnemonics.
        Duplicated shares are ignored.

        Args:
            mnemonics (str, Mnemonic object or list): Share mnemonic(s)

        Returns:
            Slip39EncryptedMasterSecret object: Encrypted master secret

        Raises:
            MnemonicChecksumError: If the checksum of a mnemonic is not valid
            ValueError: If a mnemonic is not valid or the shares cannot be combined
        """
        if isinstance(mnemonics, (str, Mnemonic)):
            mnemonics = [mnemonics]
        if len(mnemonics) == 0:
            raise ValueError("No mnemonic specified")

        decoder = Slip39MnemonicDecoder()
        # Remove duplicated shares, keeping the order
        shares = list(dict.fromkeys(decoder.Decode(mnemonic) for mnemonic in mnemonics))
        cls.__CheckCommonParameters(shares)

        first_share = shares[0]

        # Group shares
        groups: Dict[int, List[Slip39Share]] = {}
        for share in shares:
            groups.setdefault(share.group_index, []).append(share)
        if len(groups) != first_share.group_threshold:
            raise ValueError(
                f"Wrong number of groups (expected {first_share.group_threshold}, got {len(groups)})"
            )

        group_secrets = [
            (group_index, cls.__RecoverGroupSecret(group_index, group_shares))
            for group_index, group_shares in groups.items()
        ]
        return Slip39EncryptedMasterSecret(
            identifier=first_share.identifier,
            extendable=first_share.extendable,
            iteration_exponent=first_share.iteration_exponent,
            value=Slip39Shamir.RecoverSecret(first_share.group_threshold, group_secrets),
        )

    @staticmethod
    def __CheckCommonParameters(shares: List[Slip39Share]) -> None:
        """
        Check that the shares have the same common parameters.

        Args:
            shares (list[Slip39Share]): Shares

        Raises:
            ValueError: If the shares have different common parameters
        """
        first_share = shares[0]
        for share in shares[1:]:
            if (share.identifier != first_share.identifier
                    or share.extendable != first_share.extendable
                    or share.iteration_exponent != first_share.iteration_exponent):
                raise ValueError("Shares shall have the same identifier, extendable flag and iteration exponent")
            if (share.group_threshold != first_share.group_threshold
                    or share.group_count != first_share.group_count):
                raise ValueError("Shares shall have the same group threshold and count")
            if len(share.value) != len(first_share.value):
                raise ValueError("Shares shall have the same length")

    @staticmethod
    def __RecoverGroupSecret(group_index: int,
                             group_shares: List[Slip39Share]) -> bytes:
        """
        Check the shares of a group and recover the group secret.

        Args:
            group_index (int)               : Group index
            group_shares (list[Slip39Share]): Shares of the group

        Returns:
            bytes: Group secret

        Raises:
            ValueError: If the shares of the group cannot be combined
        """
        member_threshold = group_shares[0].member_threshold
        if any(share.member_threshold != member_threshold for share in group_shares):
            raise ValueError(f"Shares of group {group_index} shall have the same member threshold")
        if len({share.member_index for share in group_shares}) != len(group_shares):
            raise ValueError(f"Shares of group {group_index} shall have different member indexes")
        if len(group_shares) != member_threshold:
            raise ValueError(
                f"Wrong number of shares for group {group_index} "
                f"(expected {member_threshold}, got {len(group_shares)})"
            )

        return Slip39Shamir.RecoverSecret(member_threshold,
                                          [(share.member_index, share.value) for share in group_shares])
