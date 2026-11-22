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
Module for BIP85 deterministic entropy derivation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
"""

# Imports
from __future__ import annotations

import base64
from typing import Dict, List, Optional, Union

from bip_utils.bip.bip32 import (
    Bip32Base,
    Bip32KeyData,
    Bip32KeyIndex,
    Bip32KeyNetVersions,
    Bip32Path,
    Bip32PathParser,
    Bip32Slip10Secp256k1,
)
from bip_utils.bip.bip39 import Bip39Languages, Bip39MnemonicEncoder, Bip39WordsNum
from bip_utils.bip.bip39.bip39_mnemonic import Bip39MnemonicConst
from bip_utils.bip.bip85.bip85_drng import Bip85Drng
from bip_utils.ecc import EllipticCurveTypes, Secp256k1PrivateKey
from bip_utils.nostr import NostrNsecEncoder
from bip_utils.utils.crypto import HmacSha512
from bip_utils.utils.misc import BytesUtils
from bip_utils.utils.mnemonic import Mnemonic
from bip_utils.wif import WifEncoder


class Bip85Const:
    """Class container for BIP85 constants."""

    # Purpose
    PURPOSE: int = 83696968
    # HMAC key for computing the entropy from the derived private key
    HMAC_KEY: bytes = b"bip-entropy-from-k"
    # Maximum value of an application path element (it shall be hardened)
    PATH_ELEM_MAX_VAL: int = 2**31 - 1

    # Application numbers
    APP_BIP39: int = 39
    APP_HD_SEED_WIF: int = 2
    APP_XPRV: int = 32
    APP_HEX: int = 128169
    APP_PWD_BASE64: int = 707764
    APP_PWD_BASE85: int = 707785
    APP_DICE: int = 89101
    APP_NOSTR: int = 128002

    # Language codes for the BIP39 application (Japanese, i.e. code 1, is not supported by the BIP39 module)
    BIP39_LANG_CODES: Dict[Bip39Languages, int] = {
        Bip39Languages.ENGLISH: 0,
        Bip39Languages.KOREAN: 2,
        Bip39Languages.SPANISH: 3,
        Bip39Languages.CHINESE_SIMPLIFIED: 4,
        Bip39Languages.CHINESE_TRADITIONAL: 5,
        Bip39Languages.FRENCH: 6,
        Bip39Languages.ITALIAN: 7,
        Bip39Languages.CZECH: 8,
        Bip39Languages.PORTUGUESE: 9,
    }

    # Bytes number range for the HEX application
    HEX_NUM_BYTES_MIN: int = 16
    HEX_NUM_BYTES_MAX: int = 64
    # Password length range for the PWD BASE64 application
    PWD_BASE64_LEN_MIN: int = 20
    PWD_BASE64_LEN_MAX: int = 86
    # Password length range for the PWD BASE85 application
    PWD_BASE85_LEN_MIN: int = 10
    PWD_BASE85_LEN_MAX: int = 80
    # Minimum sides and rolls numbers for the DICE application
    DICE_SIDES_MIN: int = 2
    DICE_ROLLS_MIN: int = 1
    # Minimum identity and account index for the Nostr application (index 0 is reserved)
    NOSTR_IDX_MIN: int = 1


class Bip85:
    """
    BIP85 class.
    It derives deterministic entropy from a BIP32 master key and uses it for the applications defined by BIP85.
    """

    m_bip32_obj: Bip32Base

    #
    # Class methods for construction
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 key_net_ver: Optional[Bip32KeyNetVersions] = None) -> Bip85:
        """
        Create a Bip85 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                                : Seed bytes
            key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
                                                                (default: Bitcoin main net)

        Returns:
            Bip85 object: Bip85 object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """
        return cls(Bip32Slip10Secp256k1.FromSeed(seed_bytes, key_net_ver))

    @classmethod
    def FromExtendedKey(cls,
                        ex_key_str: str,
                        key_net_ver: Optional[Bip32KeyNetVersions] = None) -> Bip85:
        """
        Create a Bip85 object from the specified extended master key.

        Args:
            ex_key_str (str)                                  : Extended private master key string
            key_net_ver (Bip32KeyNetVersions object, optional): Bip32KeyNetVersions object
                                                                (default: Bitcoin main net)

        Returns:
            Bip85 object: Bip85 object

        Raises:
            Bip32KeyError: If the key is not valid
            ValueError: If the key is public or not a master key
        """
        return cls(Bip32Slip10Secp256k1.FromExtendedKey(ex_key_str, key_net_ver))

    #
    # Public methods
    #

    def __init__(self,
                 bip32_obj: Bip32Base) -> None:
        """
        Construct class.

        Args:
            bip32_obj (Bip32Base object): Bip32Base object (private master key on the secp256k1 curve)

        Raises:
            TypeError: If the BIP32 object is not based on the secp256k1 curve
            ValueError: If the BIP32 object is public-only or not a master key
        """
        if bip32_obj.CurveType() != EllipticCurveTypes.SECP256K1:
            raise TypeError("The BIP32 object shall be based on the secp256k1 curve")
        if bip32_obj.IsPublicOnly():
            raise ValueError("The BIP32 object shall not be public-only")
        if bip32_obj.Depth() != 0:
            raise ValueError("The BIP32 object shall be a master key")

        self.m_bip32_obj = bip32_obj

    def Bip32Object(self) -> Bip32Base:
        """
        Return the BIP32 object.

        Returns:
            Bip32Base object: Bip32Base object
        """
        return self.m_bip32_obj

    def DeriveEntropy(self,
                      path: Union[str, Bip32Path]) -> bytes:
        """
        Derive entropy from the specified path, as defined by BIP85.
        The path shall be fully hardened (e.g. m/83696968'/0'/0').

        Args:
            path (str or Bip32Path object): Path

        Returns:
            bytes: Entropy bytes (64-byte)

        Raises:
            Bip32PathError: If the path is not valid
            Bip32KeyError: If the path results in an invalid key
            ValueError: If the path is empty or not fully hardened
        """
        path = Bip32PathParser.Parse(path) if isinstance(path, str) else path
        if path.Length() == 0 or not all(elem.IsHardened() for elem in path):
            raise ValueError("The path shall be non-empty and fully hardened")

        priv_key_bytes = self.m_bip32_obj.DerivePath(path).PrivateKey().Raw().ToBytes()
        return HmacSha512.QuickDigest(Bip85Const.HMAC_KEY, priv_key_bytes)

    def Bip39(self,
              lang: Bip39Languages,
              words_num: Union[int, Bip39WordsNum],
              index: int) -> Mnemonic:
        """
        Derive a BIP39 mnemonic (application 39').
        Path: m/83696968'/39'/{language}'/{words_num}'/{index}'

        Args:
            lang (Bip39Languages)           : Language (all the BIP39 languages except Japanese)
            words_num (int or Bip39WordsNum): Number of words (12, 15, 18, 21, 24)
            index (int)                     : Index

        Returns:
            Mnemonic object: Mnemonic object

        Raises:
            TypeError: If the language is not a Bip39Languages enum
            ValueError: If the words number or the index is not valid
        """
        if not isinstance(lang, Bip39Languages):
            raise TypeError("Language is not an enumerative of Bip39Languages")
        if words_num not in Bip39MnemonicConst.MNEMONIC_WORD_NUM:
            raise ValueError(f"Words number for mnemonic ({words_num}) is not valid")

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_BIP39,
                                                Bip85Const.BIP39_LANG_CODES[lang],
                                                words_num,
                                                index)
        # Truncate the entropy to the length required by the words number
        entropy_byte_len = (words_num * Bip39MnemonicConst.WORD_BIT_LEN - words_num // 3) // 8
        return Bip39MnemonicEncoder(lang).Encode(entropy_bytes[:entropy_byte_len])

    def HdSeedWif(self,
                  index: int) -> str:
        """
        Derive a HD-Seed WIF (application 2'), i.e. a private key in compressed WIF format (Bitcoin main net).
        Path: m/83696968'/2'/{index}'

        Args:
            index (int): Index

        Returns:
            str: Private key in WIF format

        Raises:
            ValueError: If the index or the derived private key is not valid
        """
        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_HD_SEED_WIF, index)
        return WifEncoder.Encode(entropy_bytes[:Secp256k1PrivateKey.Length()])

    def Xprv(self,
             index: int) -> str:
        """
        Derive a XPRV (application 32'), i.e. an extended private master key.
        Path: m/83696968'/32'/{index}'
        The key is serialized with the same key net versions of the master key (e.g. a test net master key results
        in a TPRV).

        Args:
            index (int): Index

        Returns:
            str: Extended private master key

        Raises:
            ValueError: If the index is not valid
            Bip32KeyError: If the derived private key is not valid
        """
        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_XPRV, index)
        # The first half is the chain code and the second half is the private key (reverse order with respect to BIP32)
        half_len = len(entropy_bytes) // 2
        return Bip32Slip10Secp256k1.FromPrivateKey(
            entropy_bytes[half_len:],
            Bip32KeyData(chain_code=entropy_bytes[:half_len]),
            self.m_bip32_obj.KeyNetVersions()
        ).PrivateKey().ToExtended()

    def Hex(self,
            num_bytes: int,
            index: int) -> str:
        """
        Derive entropy in hex format (application 128169').
        Path: m/83696968'/128169'/{num_bytes}'/{index}'

        Args:
            num_bytes (int): Number of bytes (16 - 64)
            index (int)    : Index

        Returns:
            str: Entropy in hex format

        Raises:
            ValueError: If the bytes number or the index is not valid
        """
        self.__ValidateRange("Bytes number", num_bytes, Bip85Const.HEX_NUM_BYTES_MIN, Bip85Const.HEX_NUM_BYTES_MAX)

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_HEX, num_bytes, index)
        return BytesUtils.ToHexString(entropy_bytes[:num_bytes])

    def PwdBase64(self,
                  pwd_len: int,
                  index: int) -> str:
        """
        Derive a password in base64 format (application 707764').
        Path: m/83696968'/707764'/{pwd_len}'/{index}'

        Args:
            pwd_len (int): Password length (20 - 86)
            index (int)  : Index

        Returns:
            str: Password

        Raises:
            ValueError: If the password length or the index is not valid
        """
        self.__ValidateRange("Password length", pwd_len, Bip85Const.PWD_BASE64_LEN_MIN, Bip85Const.PWD_BASE64_LEN_MAX)

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_PWD_BASE64, pwd_len, index)
        return base64.b64encode(entropy_bytes).decode()[:pwd_len]

    def PwdBase85(self,
                  pwd_len: int,
                  index: int) -> str:
        """
        Derive a password in base85 format (application 707785').
        Path: m/83696968'/707785'/{pwd_len}'/{index}'

        Args:
            pwd_len (int): Password length (10 - 80)
            index (int)  : Index

        Returns:
            str: Password

        Raises:
            ValueError: If the password length or the index is not valid
        """
        self.__ValidateRange("Password length", pwd_len, Bip85Const.PWD_BASE85_LEN_MIN, Bip85Const.PWD_BASE85_LEN_MAX)

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_PWD_BASE85, pwd_len, index)
        return base64.b85encode(entropy_bytes).decode()[:pwd_len]

    def Dice(self,
             sides: int,
             rolls: int,
             index: int) -> List[int]:
        """
        Derive dice rolls (application 89101').
        Path: m/83696968'/89101'/{sides}'/{rolls}'/{index}'
        Rolls are zero-indexed, so a N-sided dice produces values in the range [0, N - 1].

        Args:
            sides (int): Number of sides of the dice (at least 2)
            rolls (int): Number of rolls (at least 1)
            index (int): Index

        Returns:
            list[int]: Rolls

        Raises:
            ValueError: If the sides number, the rolls number or the index is not valid
        """
        self.__ValidateRange("Sides number", sides, Bip85Const.DICE_SIDES_MIN, Bip85Const.PATH_ELEM_MAX_VAL)
        self.__ValidateRange("Rolls number", rolls, Bip85Const.DICE_ROLLS_MIN, Bip85Const.PATH_ELEM_MAX_VAL)

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_DICE, sides, rolls, index)

        # Bits per roll is ceil(log2(sides))
        bits_per_roll = (sides - 1).bit_length()
        bytes_per_roll = (bits_per_roll + 7) // 8

        drng = Bip85Drng(entropy_bytes)
        roll_vals: List[int] = []
        while len(roll_vals) < rolls:
            # Keep only the most significant bits
            trial = BytesUtils.ToInteger(drng.Read(bytes_per_roll)) >> (bytes_per_roll * 8 - bits_per_roll)
            # Skip trials greater than or equal to the number of sides
            if trial < sides:
                roll_vals.append(trial)
        return roll_vals

    def Nostr(self,
              identity: int,
              account_idx: int) -> str:
        """
        Derive a Nostr private key in nsec format (application 128002').
        Path: m/83696968'/128002'/{identity}'/{account_idx}'
        Index 0 is reserved for both the identity and the account index, so they start from 1.

        Args:
            identity (int)   : Identity index (at least 1)
            account_idx (int): Account index (at least 1)

        Returns:
            str: Private key in nsec format

        Raises:
            ValueError: If the identity index, the account index or the derived private key is not valid
        """
        self.__ValidateRange("Identity index", identity, Bip85Const.NOSTR_IDX_MIN, Bip85Const.PATH_ELEM_MAX_VAL)
        self.__ValidateRange("Account index", account_idx, Bip85Const.NOSTR_IDX_MIN, Bip85Const.PATH_ELEM_MAX_VAL)

        entropy_bytes = self.__DeriveAppEntropy(Bip85Const.APP_NOSTR, identity, account_idx)
        return NostrNsecEncoder.Encode(entropy_bytes[:Secp256k1PrivateKey.Length()])

    #
    # Private methods
    #

    def __DeriveAppEntropy(self,
                           app_num: int,
                           *path_elems: int) -> bytes:
        """
        Derive entropy for the specified application.
        Path: m/83696968'/{app_num}'/{path_elems[0]}'/.../{path_elems[n]}'

        Args:
            app_num (int)   : Application number
            *path_elems (int): Application path elements (not hardened)

        Returns:
            bytes: Entropy bytes

        Raises:
            ValueError: If a path element is not valid
        """
        for path_elem in path_elems:
            self.__ValidateRange("Path element", path_elem, 0, Bip85Const.PATH_ELEM_MAX_VAL)

        return self.DeriveEntropy(
            Bip32Path(
                [Bip32KeyIndex.HardenIndex(elem) for elem in (Bip85Const.PURPOSE, app_num, *path_elems)]
            )
        )

    @staticmethod
    def __ValidateRange(name: str,
                        value: int,
                        min_val: int,
                        max_val: int) -> None:
        """
        Validate that the specified value is in range.

        Args:
            name (str)   : Value name (for the error message)
            value (int)  : Value
            min_val (int): Minimum value
            max_val (int): Maximum value

        Raises:
            ValueError: If the value is not in range
        """
        if value < min_val or value > max_val:
            raise ValueError(f"{name} ({value}) is not valid, it shall be in the range [{min_val}, {max_val}]")
