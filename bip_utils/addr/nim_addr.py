
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

"""Module for Nimiq address encoding/decoding."""

# Imports
from typing import Any, Union

from bip_utils.addr.addr_dec_utils import AddrDecUtils, ChecksumPositions
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.crypto import Blake2b256
from bip_utils.utils.misc import Base32Decoder, Base32Encoder


class NimAddrConst:
    """Class container for Nimiq address constants."""

    # Length of an address group of characters
    ADDR_GROUP_LEN: int = 4
    # Encoded checksum length
    CHECKSUM_ENC_LEN: int = 2
    # Alphabet for base32
    BASE32_ALPHABET: str = "0123456789ABCDEFGHJKLMNPQRSTUVXY"
    # Hash length in bytes
    HASH_BYTE_LEN: int = 20
    # Encoded hah length
    HASH_ENC_LEN: int = 32


class _NimAddrUtils:
    """Class container for Nimiq address utility functions."""

    @classmethod
    def ComputeChecksum(cls,
                        addr_base32: str) -> str:
        """
        Compute checksum in Nimiq format.

        Args:
            addr_base32 (str): Address base32 encoded

        Returns:
            str: Computed checksum encoded to string
        """

        # Compute checksum from address encoding
        checksum = 0
        for c in addr_base32:
            val = ord(c) - ord("0") if c.isdigit() else ord(c) - ord("7")
            checksum = cls.__AddChecksum(checksum, val)

        # Finalize checksum
        checksum = cls.__FinalizeChecksum(checksum)
        # Convert it to string
        return cls.__ChecksumToString(checksum)

    @staticmethod
    def __ChecksumToString(checksum: int) -> str:
        """
        Convert checksum to string.

        Args:
            checksum (int): Checksum

        Returns:
            str: Checksum string
        """
        return chr(ord("0") + int(checksum / 10)) + chr(ord("0") + (checksum % 10))

    @classmethod
    def __FinalizeChecksum(cls,
                           checksum: int) -> int:
        """
        Finalize checksum.

        Args:
            checksum (int): Checksum

        Returns:
            int: Finalized checksum
        """
        return 98 - cls.__AddChecksum(checksum, 232600)

    @staticmethod
    def __AddChecksum(checksum: int,
                      val: int) -> int:
        """
        Add a value to the checksum.

        Args:
            checksum (int): Checksum
            val (int)     : Value to be added

        Returns:
            int: Resulting checksum
        """
        if val == 0:
            return (checksum * 10) % 97

        remainder = val
        while remainder > 0:
            checksum *= 10
            remainder = int(remainder / 10)

        return (checksum + val) % 97


class NimAddrDecoder(IAddrDecoder):
    """
    Nimiq address decoder class.
    It allows the Nimiq address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode an Nimiq address to bytes.

        Args:
            addr (str): Address string
            **kwargs  : Not used

        Returns:
            bytes: Public key hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """

        # Remove all spaces
        addr = addr.replace(" ", "")
        # Validate and remove prefix
        addr_no_prefix = AddrDecUtils.ValidateAndRemovePrefix(addr, CoinsConf.Nimiq.ParamByKey("addr_prefix"))
        # Validate length
        AddrDecUtils.ValidateLength(addr_no_prefix,
                                    NimAddrConst.CHECKSUM_ENC_LEN + NimAddrConst.HASH_ENC_LEN)
        # Get back checksum and public key hash
        pub_key_hash_enc, checksum = AddrDecUtils.SplitPartsByChecksum(
            addr_no_prefix,
            NimAddrConst.CHECKSUM_ENC_LEN,
            ChecksumPositions.BEGINNING
        )
        # Validate checksum
        AddrDecUtils.ValidateChecksum(pub_key_hash_enc, checksum, _NimAddrUtils.ComputeChecksum)

        return Base32Decoder.Decode(pub_key_hash_enc, NimAddrConst.BASE32_ALPHABET)


class NimAddrEncoder(IAddrEncoder):
    """
    Nimiq address encoder class.
    It allows the Nimiq address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Nimiq address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object
            **kwargs                     : Not used

        Returns:
            str: Address string

        Raises:
            ValueError: If the public key is not valid
            TypeError: If the public key is not ed25519
        """
        pub_key_obj = AddrKeyValidator.ValidateAndGetEd25519Key(pub_key)
        pub_key_bytes = pub_key_obj.RawCompressed().ToBytes()[1:]
        pub_key_hash_bytes = Blake2b256.QuickDigest(pub_key_bytes)[:NimAddrConst.HASH_BYTE_LEN]

        pub_key_hash_enc = Base32Encoder.EncodeNoPadding(pub_key_hash_bytes, NimAddrConst.BASE32_ALPHABET)
        pub_key_hash_enc_grouped = " ".join(
            pub_key_hash_enc[i:i + NimAddrConst.ADDR_GROUP_LEN]
            for i in range(0, len(pub_key_hash_enc), NimAddrConst.ADDR_GROUP_LEN)
        )
        checksum = _NimAddrUtils.ComputeChecksum(pub_key_hash_enc)

        return CoinsConf.Nimiq.ParamByKey("addr_prefix") + checksum + " " + pub_key_hash_enc_grouped


# Deprecated: only for compatibility, Encoder class shall be used instead
NimAddr = NimAddrEncoder
