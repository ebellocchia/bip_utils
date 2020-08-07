# Copyright (c) 2014 Corgan Labs, 2020 Emanuele Bellocchia
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


# Imports
import ecdsa
from ecdsa.curves                 import SECP256k1
from ecdsa.ecdsa                  import generator_secp256k1, int_to_string, string_to_int
from bip_utils.bip.bip32_ex       import Bip32KeyError, Bip32PathError
from bip_utils.bip.bip32_utils    import Bip32Utils
from bip_utils.bip.bip32_path     import Bip32PathParser
from bip_utils.bip.bip32_key_ser  import Bip32KeyDeserializer
from bip_utils.bip.bip_keys       import BipPrivateKey, BipPublicKey
from bip_utils.conf.bip_coin_conf import Bip32Conf
from bip_utils.utils              import CryptoUtils


class Bip32Const:
    """ Class container for BIP32 constants. """

    # SECP256k1 curve order
    CURVE_ORDER          = generator_secp256k1.order()

    # Fingerprint length in bytes
    FINGERPRINT_BYTE_LEN = 4
    # Fingerprint of master key
    MASTER_FINGERPRINT   = b"\x00\x00\x00\x00"
    # Minimum length in bits for seed
    SEED_MIN_BIT_LEN     = 128
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY  = b"Bitcoin seed"


class Bip32:
    """ BIP32 class. It allows master key generation and children keys derivation in according to BIP-0032.
    BIP-0032 specifications: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """

    #
    # Static methods
    #

    @staticmethod
    def FromSeed(seed_bytes, key_net_ver = Bip32Conf.KEY_NET_VER.Main()):
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).

        Args:
            seed_bytes (bytes)                           : Seed bytes
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            ValueError: If the seed is too short
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Check seed length
        if len(seed_bytes) * 8 < Bip32Const.SEED_MIN_BIT_LEN:
            raise ValueError("Seed length is too small, it shall be at least %d bit" % Bip32Const.SEED_MIN_BIT_LEN)

        # Compute HMAC
        hmac = CryptoUtils.HmacSha512(Bip32Const.MASTER_KEY_HMAC_KEY, seed_bytes)
        # Create BIP32 by splitting the HMAC into two 32-byte sequences
        return Bip32(secret = hmac[:32], chain = hmac[32:], key_net_ver = key_net_ver)

    @staticmethod
    def FromSeedAndPath(seed_bytes, path, key_net_ver = Bip32Conf.KEY_NET_VER.Main()):
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.

        Args:
            seed_bytes (bytes)                           : Seed bytes
            path (str)                                   : Path
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
            Bip32KeyError: If the seed is not suitable for master key generation
        """

        # Parse path
        path_idx = Bip32PathParser.Parse(path)

        # Check result
        if len(path_idx) == 0:
            raise Bip32PathError("The specified path is not valid")

        # Create Bip32 object
        bip32_ctx = Bip32.FromSeed(seed_bytes, key_net_ver)
        # Start from 1 because the master key is already derived
        for i in range(1, len(path_idx)):
            bip32_ctx = bip32_ctx.ChildKey(path_idx[i])

        return bip32_ctx

    @staticmethod
    def FromExtendedKey(key_str, key_net_ver = Bip32Conf.KEY_NET_VER.Main()):
        """ Create a Bip32 object from the specified extended key.

        Args:
            key_str (str)                                : Extended key string
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Returns:
            Bip32 object: Bip32 object

        Raises:
            Bip32KeyError: If the key is not valid
        """

        # De-serialize key
        key_deser = Bip32KeyDeserializer(key_str)
        key_deser.DeserializeKey(key_net_ver)
        # Get key parts
        depth, fprint, index, chain, secret = key_deser.GetKeyParts()
        is_public = key_deser.IsPublic()

        # If depth is zero, fingerprint shall be the master one and child index shall be zero
        if depth == 0:
            if fprint != Bip32Const.MASTER_FINGERPRINT:
                raise Bip32KeyError("Invalid extended master key (wrong fingerprint)")
            if index != 0:
                raise Bip32KeyError("Invalid extended master key (wrong child index)")

        # If private key, remove the first byte
        if not is_public:
            if secret[0] != 0:
                raise Bip32KeyError("Invalid extended key (wrong secret)")
            secret = secret[1:]
        # If public key, recover the complete key from the compressed one
        else:
            try:
                secret = ecdsa.VerifyingKey.from_string(secret, curve = SECP256k1)
            except ecdsa.keys.MalformedPointError:
                raise Bip32KeyError("Invalid extended public key (malformed point)")

        return Bip32(
            secret      = secret,
            chain       = chain,
            depth       = depth,
            index       = index,
            fprint      = fprint,
            is_public   = is_public,
            key_net_ver = key_net_ver)

    #
    # Public methods
    #

    def __init__(self,
                 secret,
                 chain,
                 depth       = 0,
                 index       = 0,
                 fprint      = Bip32Const.MASTER_FINGERPRINT,
                 is_public   = False,
                 key_net_ver = Bip32Conf.KEY_NET_VER.Main()):
        """ Construct class from secret and chain.

        Args:
            secret (bytes)                               : Source bytes to generate the keypair
            chain (bytes)                                : 32-byte representation of the chain code
            depth (int, optional)                        : Child depth, parent increments its own by one when assigning this (default: 0)
            index (int, optional)                        : Child index (default: 0)
            fprint (bytes, optional)                     : Parent fingerprint (default: 0)
            is_public (bool, optional)                   : If true, this keypair will only contain a public key and can only create a public key chain  (default: false)
            key_net_ver (KeyNetVersions object, optional): Key net version object (Bip32 main net version by default)

        Raises:
            Bip32KeyError: If the private key constructed from the secret is not valid
        """

        if not is_public:
            # Check private key validity
            try:
                self.m_key = ecdsa.SigningKey.from_string(secret, curve = SECP256k1)
            except ecdsa.keys.MalformedPointError:
                raise Bip32KeyError("Invalid private key (malformed point)")
            # Get verifying key
            self.m_ver_key = self.m_key.get_verifying_key()
        else:
            self.m_key     = None
            self.m_ver_key = secret

        self.m_is_public     = is_public
        self.m_chain         = chain
        self.m_depth         = depth
        self.m_index         = index
        self.m_parent_fprint = fprint
        self.m_key_net_ver   = key_net_ver

    def ChildKey(self, index):
        """ Create and return a child key of the current one at the specified index.
        The index shall be hardened using HardenIndex method to use the private derivation algorithm.

        Args:
            index (int): Index

        Returns:
            Bip32 object: Child key as a new Bip32 object

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """
        return self.__CkdPriv(index) if not self.m_is_public else self.__CkdPub(index)

    def DerivePath(self, path):
        """ Derive children keys from the specified path.

        Args:
            path (str): Path

        Returns:
            Bip32 object: Bip32 object

        Raises:
            Bip32PathError: If the seed length is too short or the path is not valid
        """

        # Parse path
        path_idx = Bip32PathParser.Parse(path, True)

        # Check result
        if len(path_idx) == 0:
            raise Bip32PathError("The specified path is not valid")

        bip32_obj = self
        # Derive children keys
        for idx in path_idx:
            bip32_obj = bip32_obj.ChildKey(idx)

        return bip32_obj

    def ConvertToPublic(self):
        """ Convert a private Bip32 object into a public one. """
        self.m_key       = None
        self.m_is_public = True

    def IsPublicOnly(self):
        """ Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_is_public

    def EcdsaPrivateKey(self):
        """ Return the ECDSA private key object.

        Return:
            ecdsa.SigningKey object: ecdsa.SigningKey object

        Raises:
            Bip32KeyError: If internal key is public-only
        """
        if self.m_is_public:
            raise Bip32KeyError("Public-only deterministic keys have no private half")
        return self.m_key

    def EcdsaPublicKey(self):
        """ Return the ECDSA public key object.

        Return:
            ecdsa.VerifyingKey object: ecdsa.VerifyingKey object
        """
        return self.m_ver_key

    def PrivateKey(self):
        """ Return private key bytes.

        Returns:
            BipPrivateKey object: BipPrivateKey object

        Raises:
            Bip32KeyError: If internal key is public-only
        """
        if self.m_is_public:
            raise Bip32KeyError("Public-only deterministic keys have no private half")
        return BipPrivateKey(self)

    def PublicKey(self):
        """ Return public key bytes.

        Returns:
            BipPublicKey object: BipPublicKey object
        """
        return BipPublicKey(self)

    def KeyNetVersions(self):
        """ Get key net versions.

        Returns:
            KeyKeyNetVersions object: KeyKeyNetVersions object
        """
        return self.m_key_net_ver

    def Depth(self):
        """ Get current depth.

        Returns:
            int: Current depth
        """
        return self.m_depth

    def Index(self):
        """ Get current index.

        Returns:
            int: Current index
        """
        return self.m_index

    def Chain(self):
        """ Get current chain.

        Returns:
            bytes: Current chain
        """
        return self.m_chain

    def KeyIdentifier(self):
        """ Get key identifier.

        Returns:
            bytes: Key identifier bytes
        """
        return CryptoUtils.Hash160(self.PublicKey().RawCompressed().ToBytes())

    def FingerPrint(self):
        """ Get key fingerprint.

        Returns:
            bytes: Key fingerprint bytes
        """
        return self.KeyIdentifier()[:Bip32Const.FINGERPRINT_BYTE_LEN]

    def ParentFingerPrint(self):
        """ Get parent fingerprint.

        Returns:
            bytes: Parent fingerprint bytes
        """
        return self.m_parent_fprint

    #
    # Private methods
    #

    def __CkdPriv(self, index):
        """ Create a child key of the specified index.

        Args:
            index (int): Index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index results in an invalid key
        """

        # Index as bytes
        index_bytes = index.to_bytes(4, "big")

        # Data for HMAC
        if Bip32Utils.IsHardenedIndex(index):
            data = b"\x00" + self.m_key.to_string() + index_bytes
        else:
            data = self.PublicKey().RawCompressed().ToBytes() + index_bytes

        # Compute HMAC halves
        i_l, i_r = self.__HmacHalves(data)

        # Construct new key secret from i_l and current private key
        i_l_int = string_to_int(i_l)
        key_int = string_to_int(self.m_key.to_string())
        new_key_int = (i_l_int + key_int) % Bip32Const.CURVE_ORDER

        # Convert to string and left pad with zeros
        secret = int_to_string(new_key_int)
        secret = b"\x00" * (32 - len(secret)) + secret

        # Construct and return a new Bip32 object
        return Bip32(secret      = secret,
                     chain       = i_r,
                     depth       = self.m_depth + 1,
                     index       = index,
                     fprint      = self.FingerPrint(),
                     is_public   = False,
                     key_net_ver = self.m_key_net_ver)

    def __CkdPub(self, index):
        """ Create a publicly derived child key of the specified index.

        Args:
            index (int): Index

        Returns:
            Bip32 object: Bip32 object constructed with the child parameters

        Raises:
            Bip32KeyError: If the index is hardened or results in an invalid key
        """

        # Check if index is hardened
        if Bip32Utils.IsHardenedIndex(index):
            raise Bip32KeyError("Public child derivation cannot be used to create a hardened child key")

        # Data for HMAC, same of __CkdPriv() for public child key
        data = self.PublicKey().RawCompressed().ToBytes() + index.to_bytes(4, "big")

        # Get HMAC of data
        i_l, i_r = self.__HmacHalves(data)

        # Construct curve point i_l*G+K
        point = string_to_int(i_l) * generator_secp256k1 + self.m_ver_key.pubkey.point

        # Try to construct public key from the curve point
        try:
            k_i = ecdsa.VerifyingKey.from_public_point(point, curve = SECP256k1)
        except:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index")

        # Construct and return a new Bip32 object
        return Bip32(secret      = k_i,
                     chain       = i_r,
                     depth       = self.m_depth + 1,
                     index       = index,
                     fprint      = self.FingerPrint(),
                     is_public   = True,
                     key_net_ver = self.m_key_net_ver)

    def __HmacHalves(self, data_bytes):
        """ Calculate the HMAC-SHA512 of input data using the chain code as key and returns a tuple of the left and right halves of the HMAC.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            tuple: Left and right halves of the HMAC
        """

        # Use chain as HMAC key
        hmac = CryptoUtils.HmacSha512(self.m_chain, data_bytes)
        return (hmac[:32], hmac[32:])
