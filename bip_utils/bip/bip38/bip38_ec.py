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

"""
Module for BIP38 encryption/decryption.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
"""

# Imports
import os
from typing import Optional, Tuple

from bip_utils.base58 import Base58Decoder, Base58Encoder
from bip_utils.bip.bip38.bip38_addr import Bip38Addr, Bip38PubKeyModes
from bip_utils.ecc import Secp256k1, Secp256k1PrivateKey, Secp256k1PublicKey
from bip_utils.utils.crypto import AesEcbDecrypter, AesEcbEncrypter, DoubleSha256, Scrypt
from bip_utils.utils.misc import BitUtils, BytesUtils, IntegerUtils, StringUtils


class Bip38EcConst:
    """Class container for BIP38 EC constants."""

    # Minimum/Maximum values for lot number
    LOT_NUM_MIN_VAL: int = 0
    LOT_NUM_MAX_VAL: int = 1048575
    # Minimum/Maximum values for sequence number
    SEQ_NUM_MIN_VAL: int = 0
    SEQ_NUM_MAX_VAL: int = 4095

    # Owner salt lengths
    OWNER_SALT_WITH_LOT_SEQ_BYTE_LEN: int = 4
    OWNER_SALT_NO_LOT_SEQ_BYTE_LEN: int = 8

    # Intermediate passphrase encrypted length in byte
    INT_PASS_ENC_BYTE_LEN: int = 49
    # Magic for intermediate passphrase
    INT_PASS_MAGIC_WITH_LOT_SEQ = b"\x2c\xe9\xb3\xe1\xff\x39\xe2\x51"
    INT_PASS_MAGIC_NO_LOT_SEQ = b"\x2c\xe9\xb3\xe1\xff\x39\xe2\x53"

    # Seedb byte length
    SEED_B_BYTE_LEN: int = 24

    # Encrypted length
    ENC_BYTE_LEN: int = 39
    # Encrypted prefix
    ENC_KEY_PREFIX: bytes = b"\x01\x43"

    # Bit number for flags in flagbyte
    FLAG_BIT_COMPRESSED: int = 5
    FLAG_BIT_LOT_SEQ: int = 2

    # Parameters for scrypt algorithm for computing prefactor
    SCRYPT_PREFACTOR_KEY_LEN: int = 32
    SCRYPT_PREFACTOR_N: int = 16384
    SCRYPT_PREFACTOR_P: int = 8
    SCRYPT_PREFACTOR_R: int = 8
    # Parameters for scrypt algorithm for deriving key halves
    SCRYPT_HALVES_KEY_LEN: int = 64
    SCRYPT_HALVES_N: int = 1024
    SCRYPT_HALVES_P: int = 1
    SCRYPT_HALVES_R: int = 1


class _Bip38EcUtils:
    """Class container for BIP38 EC utility functions."""

    @staticmethod
    def OwnerEntropyWithLotSeq(lot_num: int,
                               sequence_num: int) -> bytes:
        """
        Compute the owner entropy as specified in BIP38 (with EC multiplication) with lot and sequence numbers.

        Args:
            lot_num (int)     : Lot number
            sequence_num (int): Sequence number

        Returns:
            bytes: Owner entropy

        Raises:
            ValueError: If lot or sequence number is not valid
        """

        # Check lot and sequence numbers
        if lot_num < Bip38EcConst.LOT_NUM_MIN_VAL or lot_num > Bip38EcConst.LOT_NUM_MAX_VAL:
            raise ValueError(f"Invalid lot number ({lot_num})")
        if sequence_num < Bip38EcConst.SEQ_NUM_MIN_VAL or sequence_num > Bip38EcConst.SEQ_NUM_MAX_VAL:
            raise ValueError(f"Invalid sequence number ({sequence_num})")

        # Generate random owner salt (4 bytes)
        owner_salt = os.urandom(Bip38EcConst.OWNER_SALT_WITH_LOT_SEQ_BYTE_LEN)
        # Compute lot sequence
        lot_sequence = IntegerUtils.ToBytes((lot_num * (Bip38EcConst.SEQ_NUM_MAX_VAL + 1)) + sequence_num,
                                            bytes_num=4)
        # Compute owner entropy
        return owner_salt + lot_sequence

    @staticmethod
    def OwnerEntropyNoLotSeq() -> bytes:
        """
        Compute the owner entropy as specified in BIP38 (with EC multiplication) without lot and sequence numbers.

        Returns:
            bytes: Owner entropy
        """

        # Generate random owner salt (8 bytes)
        owner_salt = os.urandom(Bip38EcConst.OWNER_SALT_NO_LOT_SEQ_BYTE_LEN)
        # Owner entropy is owner salt
        return owner_salt

    @staticmethod
    def OwnerSaltFromEntropy(owner_entropy: bytes,
                             has_lot_seq: bool) -> bytes:
        """
        Get owner salt from owner entropy.

        Args:
            owner_entropy (bytes): Owner entropy
            has_lot_seq (bool)   : True if lot and sequence numbers are present, false otherwise

        Returns:
            bytes: Owner salt
        """
        return owner_entropy if not has_lot_seq else owner_entropy[:Bip38EcConst.OWNER_SALT_WITH_LOT_SEQ_BYTE_LEN]

    @staticmethod
    def PassFactor(passphrase: str,
                   owner_entropy: bytes,
                   has_lot_seq: bool) -> bytes:
        """
        Compute the passfactor as specified in BIP38 (with EC multiplication).

        Args:
            passphrase (str)     : Passphrase
            owner_entropy (bytes): Owner entropy
            has_lot_seq (bool)   : True if lot and sequence numbers are present, false otherwise

        Returns:
            bytes: Passfactor
        """

        # Compute the prefactor
        prefactor = Scrypt.DeriveKey(StringUtils.NormalizeNfc(passphrase),
                                     _Bip38EcUtils.OwnerSaltFromEntropy(owner_entropy, has_lot_seq),
                                     key_len=Bip38EcConst.SCRYPT_PREFACTOR_KEY_LEN,
                                     n=Bip38EcConst.SCRYPT_PREFACTOR_N,
                                     r=Bip38EcConst.SCRYPT_PREFACTOR_P,
                                     p=Bip38EcConst.SCRYPT_PREFACTOR_R)
        # Compute the passfactor
        if has_lot_seq:
            passfactor = DoubleSha256.QuickDigest(prefactor + owner_entropy)
        else:
            passfactor = prefactor

        return passfactor

    @staticmethod
    def PassPoint(passfactor: bytes) -> bytes:
        """
        Compute the passpoint as specified in BIP38 (with EC multiplication).

        Args:
            passfactor (bytes): Passfactor

        Returns:
            bytes: Passpoint bytes in compressed format
        """

        # Compute passpoint
        passpoint = Secp256k1PublicKey.FromPoint(Secp256k1.Generator() * BytesUtils.ToInteger(passfactor))
        # Return it as a compressed public key
        return passpoint.RawCompressed().ToBytes()

    @staticmethod
    def DeriveKeyHalves(passpoint: bytes,
                        address_hash: bytes,
                        owner_entropy: bytes) -> Tuple[bytes, bytes]:
        """
        Compute the scrypt as specified in BIP38 (without EC multiplication)and derive the two key halves.

        Args:
            passpoint (bytes)    : Passpoint
            address_hash (bytes) : Address hash
            owner_entropy (bytes): Owner entropy

        Returns:
            tuple[bytes, bytes]: Derived key halves
        """

        # Derive a key from passpoint, address hash and owner entropy
        key = Scrypt.DeriveKey(passpoint,
                               address_hash + owner_entropy,
                               key_len=Bip38EcConst.SCRYPT_HALVES_KEY_LEN,
                               n=Bip38EcConst.SCRYPT_HALVES_N,
                               r=Bip38EcConst.SCRYPT_HALVES_R,
                               p=Bip38EcConst.SCRYPT_HALVES_P)
        # Split the resulting 64 bytes in half
        derived_half_1 = key[:Bip38EcConst.SCRYPT_HALVES_KEY_LEN // 2]
        derived_half_2 = key[Bip38EcConst.SCRYPT_HALVES_KEY_LEN // 2:]

        return derived_half_1, derived_half_2


class Bip38EcKeysGenerator:
    """
    BIP38 keys generator class.
    It generates intermediate codes and private keys using the algorithm specified in BIP38 with EC multiplication.
    """

    @staticmethod
    def GenerateIntermediatePassphrase(passphrase: str,
                                       lot_num: Optional[int] = None,
                                       sequence_num: Optional[int] = None) -> str:
        """
        Generate an intermediate passphrase from the user passphrase as specified in BIP38.

        Args:
            passphrase (str)            : Passphrase
            lot_num (int, optional)     : Lot number
            sequence_num (int, optional): Sequence number

        Returns:
            str: Intermediate passphrase encoded in base58
        """

        # Get if lot and sequence are used
        has_lot_seq = lot_num is not None and sequence_num is not None

        # Compute owner entropy and salt
        # We can ignore the mypy warning because has_lot_seq checks for variables for being not None
        owner_entropy = (_Bip38EcUtils.OwnerEntropyWithLotSeq(lot_num, sequence_num)    # type: ignore [arg-type]
                         if has_lot_seq
                         else _Bip38EcUtils.OwnerEntropyNoLotSeq())
        # Compute passpoint
        passfactor = _Bip38EcUtils.PassFactor(passphrase, owner_entropy, has_lot_seq)
        passpoint = _Bip38EcUtils.PassPoint(passfactor)

        # Get magic
        magic = Bip38EcConst.INT_PASS_MAGIC_WITH_LOT_SEQ if has_lot_seq else Bip38EcConst.INT_PASS_MAGIC_NO_LOT_SEQ

        # Build and encode intermediate passphrase
        return Base58Encoder.CheckEncode(magic + owner_entropy + passpoint)

    @staticmethod
    def GeneratePrivateKey(int_passphrase: str,
                           pub_key_mode: Bip38PubKeyModes) -> str:
        """
        Generate a random encrypted private key from the intermediate passphrase.

        Args:
            int_passphrase (str)           : Intermediate passphrase
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            str: Encrypted private key

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the intermediate code is not valid
        """

        # Decode intermediate passphrase
        int_passphrase_bytes = Base58Decoder.CheckDecode(int_passphrase)

        # Check length
        if len(int_passphrase_bytes) != Bip38EcConst.INT_PASS_ENC_BYTE_LEN:
            raise ValueError(f"Invalid intermediate code length ({len(int_passphrase_bytes)})")

        # Get all the parts back
        magic = int_passphrase_bytes[:8]
        owner_entropy = int_passphrase_bytes[8:16]
        passpoint = Secp256k1PublicKey.FromBytes(int_passphrase_bytes[16:])

        # Check magic
        if magic not in (Bip38EcConst.INT_PASS_MAGIC_NO_LOT_SEQ, Bip38EcConst.INT_PASS_MAGIC_WITH_LOT_SEQ):
            raise ValueError(f"Invalid magic ({BytesUtils.ToHexString(magic)})")

        # Generate seedb
        seedb = os.urandom(Bip38EcConst.SEED_B_BYTE_LEN)
        # Compute factorb from seedb
        factorb = DoubleSha256.QuickDigest(seedb)

        # Compute address hash
        address_hash = Bip38Addr.AddressHash(
            Secp256k1PublicKey.FromPoint(passpoint.Point() * BytesUtils.ToInteger(factorb)),
            pub_key_mode
        )
        # Derive key halves from the passpoint, address hash and owner entropy
        derived_half_1, derived_half_2 = _Bip38EcUtils.DeriveKeyHalves(passpoint.RawCompressed().ToBytes(),
                                                                       address_hash,
                                                                       owner_entropy)
        # Encrypt seedb in two parts
        encrypted_part_1, encrypted_part_2 = Bip38EcKeysGenerator.__EncryptSeedb(seedb,
                                                                                 derived_half_1,
                                                                                 derived_half_2)

        # Get flagbyte by setting bits
        flagbyte = Bip38EcKeysGenerator.__SetFlagbyteBits(magic, pub_key_mode)
        # Concatenate all parts
        enc_key_bytes = (Bip38EcConst.ENC_KEY_PREFIX + flagbyte + address_hash
                         + owner_entropy + encrypted_part_1[:8] + encrypted_part_2)

        # Encode in Base58Check
        return Base58Encoder.CheckEncode(enc_key_bytes)

    @staticmethod
    def __EncryptSeedb(seedb: bytes,
                       derived_half_1: bytes,
                       derived_half_2: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt seedb in two parts.

        Args:
            seedb (bytes)         : Seedb
            derived_half_1 (bytes): First half of derived key
            derived_half_2 (bytes): Second half of derived key

        Returns:
            tuple[bytes, bytes]: Two encrypted parts
        """

        # Use derived_half_2 as AES key
        aes_enc = AesEcbEncrypter(derived_half_2)
        aes_enc.AutoPad(False)

        # Encrypt the first part: seedb[0...15] xor derived_half_1[0...15]
        encrypted_part_1 = aes_enc.Encrypt(BytesUtils.Xor(seedb[:16], derived_half_1[:16]))
        # Encrypt the second part: (encrypted_part_1[8...15] + seedb[16...23])) xor derivedhalf1[16...31]
        encrypted_part_2 = aes_enc.Encrypt(BytesUtils.Xor(encrypted_part_1[8:] + seedb[16:], derived_half_1[16:]))

        return encrypted_part_1, encrypted_part_2

    @staticmethod
    def __SetFlagbyteBits(magic: bytes,
                          pub_key_mode: Bip38PubKeyModes) -> bytes:
        """
        Set flagbyte bits and return it.

        Args:
            magic (bytes)                  : Magic
            pub_key_mode (Bip38PubKeyModes): Public key mode

        Returns:
            bytes: Flagbyte
        """
        flagbyte_int = 0
        if pub_key_mode == Bip38PubKeyModes.COMPRESSED:
            flagbyte_int = BitUtils.SetBit(flagbyte_int, Bip38EcConst.FLAG_BIT_COMPRESSED)
        if magic == Bip38EcConst.INT_PASS_MAGIC_WITH_LOT_SEQ:
            flagbyte_int = BitUtils.SetBit(flagbyte_int, Bip38EcConst.FLAG_BIT_LOT_SEQ)

        return IntegerUtils.ToBytes(flagbyte_int)


class Bip38EcDecrypter:
    """
    BIP38 decrypter class.
    It decrypts a private key using the algorithm specified in BIP38 with EC multiplication.
    """

    @staticmethod
    def Decrypt(priv_key_enc: str,  # pylint: disable=too-many-locals
                passphrase: str) -> Tuple[bytes, Bip38PubKeyModes]:
        """
        Decrypt the specified private key.

        Args:
            priv_key_enc (str): Encrypted private key bytes
            passphrase (str)  : Passphrase

        Returns:
            tuple[bytes, Bip38PubKeyModes]: Decrypted private key (index 0), public key mode (index 1)

        Raises:
            Base58ChecksumError: If base58 checksum is not valid
            ValueError: If the encrypted key is not valid
        """

        # Decode private key
        priv_key_enc_bytes = Base58Decoder.CheckDecode(priv_key_enc)
        # Check encrypted length
        if len(priv_key_enc_bytes) != Bip38EcConst.ENC_BYTE_LEN:
            raise ValueError(f"Invalid encrypted length ({len(priv_key_enc_bytes)})")

        # Get all the parts back
        prefix = priv_key_enc_bytes[:2]
        flagbyte = IntegerUtils.ToBytes(priv_key_enc_bytes[2])
        address_hash = priv_key_enc_bytes[3:7]
        owner_entropy = priv_key_enc_bytes[7:15]
        encrypted_part_1_lower = priv_key_enc_bytes[15:23]
        encrypted_part_2 = priv_key_enc_bytes[23:]

        # Check prefix
        if prefix != Bip38EcConst.ENC_KEY_PREFIX:
            raise ValueError(f"Invalid prefix ({BytesUtils.ToHexString(prefix)})")
        # Get flagbyte options
        pub_key_mode, has_lot_seq = Bip38EcDecrypter.__GetFlagbyteOptions(flagbyte)

        # Compute passfactor
        passfactor = _Bip38EcUtils.PassFactor(passphrase, owner_entropy, has_lot_seq)
        # Derive key halves from the passpoint, address hash and owner entropy
        derived_half_1, derived_half_2 = _Bip38EcUtils.DeriveKeyHalves(_Bip38EcUtils.PassPoint(passfactor),
                                                                       address_hash,
                                                                       owner_entropy)

        # Get factorb back by decrypting
        factorb = Bip38EcDecrypter.__DecryptAndGetFactorb(encrypted_part_1_lower,
                                                          encrypted_part_2,
                                                          derived_half_1,
                                                          derived_half_2)
        # Compute private key
        priv_key_bytes = Bip38EcDecrypter.__ComputePrivateKey(passfactor, factorb)

        # Verify the address hash
        address_hash_got = Bip38Addr.AddressHash(Secp256k1PrivateKey.FromBytes(priv_key_bytes).PublicKey(),
                                                 pub_key_mode)
        if address_hash != address_hash_got:
            raise ValueError(
                f"Invalid address hash (expected: {BytesUtils.ToHexString(address_hash)}, "
                f"got: {BytesUtils.ToHexString(address_hash_got)})"
            )

        return priv_key_bytes, pub_key_mode

    @staticmethod
    def __DecryptAndGetFactorb(encrypted_part_1_lower: bytes,
                               encrypted_part_2: bytes,
                               derived_half_1: bytes,
                               derived_half_2: bytes) -> bytes:
        """
        Decrypt and get back factorb.

        Args:
            encrypted_part_1_lower (bytes): Lower part of first encrypted part
            encrypted_part_2 (bytes)      : Second encrypted part
            derived_half_1 (bytes)        : First half of derived key
            derived_half_2 (bytes)        : Second half of derived key

        Returns:
            bytes: Factorb
        """

        # Use derived_half_2 as AES key
        aes_dec = AesEcbDecrypter(derived_half_2)
        aes_dec.AutoUnPad(False)

        # Decrypt the second part and get back the higher parts of seedb and encrypted half 1
        decrypted_part_2 = BytesUtils.Xor(aes_dec.Decrypt(encrypted_part_2), derived_half_1[16:])
        encrypted_part_1_higher = decrypted_part_2[:8]
        seedb_part_2 = decrypted_part_2[8:]

        # Decrypt the first part to get the lower part of seedb
        seedb_part_1 = BytesUtils.Xor(aes_dec.Decrypt(encrypted_part_1_lower + encrypted_part_1_higher),
                                      derived_half_1[:16])
        # Rebuild the complete seedb
        seedb = seedb_part_1 + seedb_part_2

        # Compute factorb from seedb
        return DoubleSha256.QuickDigest(seedb)

    @staticmethod
    def __ComputePrivateKey(passfactor: bytes,
                            factorb: bytes) -> bytes:
        """
        Compute the private key from passfactor and factorb.

        Args:
            passfactor (bytes): Passfactor
            factorb (bytes)   : Factorb

        Returns:
            bytes: Private key
        """

        # Private key: (passfactor * factorb) mod N
        priv_key_int = (BytesUtils.ToInteger(passfactor) * BytesUtils.ToInteger(factorb)) % Secp256k1.Order()
        return IntegerUtils.ToBytes(priv_key_int, bytes_num=Secp256k1PrivateKey.Length())

    @staticmethod
    def __GetFlagbyteOptions(flagbyte: bytes) -> Tuple[Bip38PubKeyModes, bool]:
        """
        Get the options from the flagbyte.

        Args:
            flagbyte (bytes): Flagbyte

        Returns:
            tuple[Bip38PubKeyModes, bool]: Public key mode (index 0), has lot/sequence numbers (index 1)
        """

        # Convert flagbyte to integer
        flagbyte_int = BytesUtils.ToInteger(flagbyte)
        # Get bit set in flagbyte
        has_lot_seq = BitUtils.IsBitSet(flagbyte_int, Bip38EcConst.FLAG_BIT_LOT_SEQ)
        pub_key_mode = (Bip38PubKeyModes.COMPRESSED
                        if BitUtils.IsBitSet(flagbyte_int, Bip38EcConst.FLAG_BIT_COMPRESSED)
                        else Bip38PubKeyModes.UNCOMPRESSED)
        # Check flagbyte
        flagbyte_int = BitUtils.ResetBit(flagbyte_int, Bip38EcConst.FLAG_BIT_LOT_SEQ)
        flagbyte_int = BitUtils.ResetBit(flagbyte_int, Bip38EcConst.FLAG_BIT_COMPRESSED)
        if flagbyte_int != 0:
            raise ValueError(f"Invalid flagbyte ({BytesUtils.ToHexString(flagbyte)})")

        return pub_key_mode, has_lot_seq
