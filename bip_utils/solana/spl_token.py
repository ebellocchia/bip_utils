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

"""Module for getting account addresses of SPL tokens."""

#
# Imports
#
from typing import List

from bip_utils.addr import SolAddrDecoder
from bip_utils.base58 import Base58Encoder
from bip_utils.ecc import Ed25519PublicKey
from bip_utils.utils.crypto import Sha256
from bip_utils.utils.misc import IntegerUtils


#
# Classes
#

class SplTokenConst:
    """Class container for SPL token constants."""

    # Default program ID
    DEF_PROGRAM_ID: str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    # Default token program ID
    DEF_TOKEN_PROGRAM_ID: str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    # Program derived address marker
    PDA_MARKER: bytes = b"ProgramDerivedAddress"
    # Maximum seed bump value
    SEED_BUMP_MAX_VAL: int = 2 ** 8 - 1
    # Maximum number of seeds
    SEEDS_MAX_NUM: int = 16


class SplToken:
    """
    SPL token class.
    It provides methods for getting the account address associated to a SPL token.
    """

    @classmethod
    def GetAssociatedTokenAddress(cls,
                                  wallet_addr: str,
                                  token_mint_addr: str) -> str:
        """
        Get the account address associated to the specified SPL token.

        Args:
            wallet_addr (str)    : Wallet address
            token_mint_addr (str): Token mint address

        Returns:
            str: Associated account address

        Raises:
            ValueError: If the account address cannot be found or the specified addresses are not valid
        """
        return cls.GetAssociatedTokenAddressWithProgramId(
            wallet_addr,
            token_mint_addr,
            SplTokenConst.DEF_TOKEN_PROGRAM_ID
        )

    @classmethod
    def GetAssociatedTokenAddressWithProgramId(cls,
                                               wallet_addr: str,
                                               token_mint_addr: str,
                                               token_program_id: str) -> str:
        """
        Get the account address associated to the specified SPL token and token program ID.

        Args:
            wallet_addr (str)     : Wallet address
            token_mint_addr (str) : Token mint address
            token_program_id (str): Token program ID

        Returns:
            str: Associated account address

        Raises:
            ValueError: If the account address cannot be found or the specified addresses or ID are not valid
        """
        seeds = [
            SolAddrDecoder.DecodeAddr(wallet_addr),
            SolAddrDecoder.DecodeAddr(token_program_id),
            SolAddrDecoder.DecodeAddr(token_mint_addr),
        ]
        return cls.FindPda(seeds, SplTokenConst.DEF_PROGRAM_ID)

    @classmethod
    def FindPda(cls,
                seeds: List[bytes],
                program_id: str) -> str:
        """
        Find a valid PDA (Program Derived Address) and its corresponding bump seed.

        Args:
            seeds (list[bytes]): List of seeds bytes
            program_id (str)   : Program ID

        Returns:
            str: Found PDA

        Raises:
            ValueError: If the PDA cannot be found or the specified seeds or program ID are not valid
        """

        # Check if seeds are valid
        if len(seeds) > SplTokenConst.SEEDS_MAX_NUM:
            raise ValueError(f"Seeds length is not valid ({len(seeds)})")
        for seed in seeds:
            if len(seed) > Ed25519PublicKey.CompressedLength() - 1:
                raise ValueError(f"Seed length is not valid ({len(seeds)})")

        program_id_bytes = SolAddrDecoder.DecodeAddr(program_id)
        bump_seed = SplTokenConst.SEED_BUMP_MAX_VAL
        for _ in range(SplTokenConst.SEED_BUMP_MAX_VAL):
            # Add bump to seeds
            seeds_with_bump = list(seeds)
            seeds_with_bump.append(IntegerUtils.ToBytes(bump_seed))
            # Try to create PDA
            try:
                return cls.__CreatePda(seeds_with_bump, program_id_bytes)
            except ValueError:
                # Continue with the next bump seed if PDA is not valid
                bump_seed -= 1

        # Very unlucky case
        raise ValueError("Unable to find a valid PDA")

    @staticmethod
    def __CreatePda(seeds_with_bump: List[bytes],
                    program_id_bytes: bytes) -> str:
        """
        Create a PDA (Program Derived Address) for the specified seeds and program ID.

        Args:
            seeds_with_bump (list[bytes]): List of seeds bytes with bump
            program_id_bytes (bytes)     : Program ID bytes

        Returns:
            str: Created PDA

        Raises:
            ValueError: If the created PDA is not valid
        """
        sha256 = Sha256()
        # Compute SHA256 of seeds with bump
        for seed in seeds_with_bump:
            sha256.Update(seed)
        # Compute SHA256 of program ID and PDA marker
        for elem in (program_id_bytes, SplTokenConst.PDA_MARKER):
            sha256.Update(elem)
        # Get PDA bytes
        pda_bytes = sha256.Digest()

        # A PDA shall NOT lie on the ed25519 curve, so it shall not be a valid public key
        if Ed25519PublicKey.IsValidBytes(pda_bytes):
            raise ValueError("Invalid created PDA")

        return Base58Encoder.Encode(pda_bytes)
