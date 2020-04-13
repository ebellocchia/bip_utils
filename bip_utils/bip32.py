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

# BIP-0032 specifications:
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

# Imports
import binascii
import ecdsa
from  ecdsa.curves  import SECP256k1
from  ecdsa.ecdsa   import generator_secp256k1, int_to_string, string_to_int
from .base58        import Base58Decoder, Base58Encoder
from .bip32_ex      import Bip32KeyError, Bip32PathError
from .bip32_utils   import Bip32Utils
from .bip32_path    import Bip32PathParser
from .bip32_key_ser import Bip32KeyDeserializer, Bip32KeySerializer
from .              import utils


class Bip32Const:
    """ Class container for BIP32 constants. """

    # SECP256k1 curve order
    CURVE_ORDER          = generator_secp256k1.order()
    # SECP256k1 field order
    FIELD_ORDER          = SECP256k1.curve.p()
    # Infinity point
    INFINITY             = ecdsa.ellipticcurve.INFINITY

    # Main net versions (xpub / xprv)
    MAIN_NET_VER         = {"pub" : binascii.unhexlify(b"0488b21e"), "priv" : binascii.unhexlify(b"0488ade4")}
    # Test net versions (tpub / tprv)
    TEST_NET_VER         = {"pub" : binascii.unhexlify(b"043587CF"), "priv" : binascii.unhexlify(b"04358394")}

    # Fingerprint length in bytes
    FINGERPRINT_BYTE_LEN = 4
    # Fingerprint of master key
    MASTER_FINGERPRINT   = b"\0\0\0\0"
    # Minimum length in bits for seed
    SEED_MIN_BIT_LEN     = 128
    # HMAC key for generating master key
    MASTER_KEY_HMAC_KEY  = b"Bitcoin seed"


class Bip32:
    """ BIP32 class. It allows master key generation and children keys derivation in according to BIP32. """

    @staticmethod
    def FromSeed(seed_bytes, is_testnet = False):
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed).
        ValueError is raised if the seed is too short.
        Bip32KeyError is raised if the seed is not suitable for master key generation.

        Args:
            seed_bytes (bytes)          : seed bytes
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (Bip32 object):
            Bip32 object
        """

        # Check seed length
        if len(seed_bytes) * 8 < Bip32Const.SEED_MIN_BIT_LEN:
            raise ValueError("Seed length is too small, it shall be at least %d bit" % Bip32Const.SEED_MIN_BIT_LEN)

        # Compute HMAC
        hmac = utils.HmacSha512(Bip32Const.MASTER_KEY_HMAC_KEY, seed_bytes)
        # Split it into two 32-byte sequences
        i_l, i_r = hmac[:32], hmac[32:]

        # Check i_l
        i_l_int = utils.BytesToInteger(i_l)
        if i_l_int == 0 or i_l_int >= Bip32Const.CURVE_ORDER:
            raise Bip32KeyError("Computed master key is not valid, very unlucky seed")

        # Create BIP32
        return Bip32(secret = i_l, chain = i_r, is_testnet = is_testnet)

    @staticmethod
    def FromSeedAndPath(seed_bytes, path, is_testnet = False):
        """ Create a Bip32 object from the specified seed (e.g. BIP39 seed) and path.
        Bip32PathError is raised if the seed length is too short or the path is not valid.
        Bip32KeyError is raised if the seed is not suitable for master key generation.

        Args:
            seed_bytes (bytes)          : seed bytes
            path (str)                  : path
            is_testnet (bool, optional) : true if test net, false if main net (default value)

        Returns (Bip32 object):
            Bip32 object
        """

        # Parse path
        path_idx = Bip32PathParser.Parse(path)

        # Check result
        if len(path_idx) == 0:
            raise Bip32PathError("The specified path is not valid")

        # Create Bip32 object
        bip32_ctx = Bip32.FromSeed(seed_bytes, is_testnet)
        # Start from 1 because the master key is already derived
        for i in range(1, len(path_idx)):
            bip32_ctx = bip32_ctx.ChildKey(path_idx[i])

        return bip32_ctx

    @staticmethod
    def FromExtendedKey(key_str,
                        is_testnet   = False,
                        main_net_ver = Bip32Const.MAIN_NET_VER,
                        test_net_ver = Bip32Const.TEST_NET_VER):
        """ Create a Bip32 object from the specified extended key.
        Bip32KeyError is raised if the key is not valid.

        Args:
            key_str (str)                 : extended key string
            is_testnet (bool, optional)   : true if test net, false if main net (default value)
            main_net_ver (dict, optional) : dictionary containg public (key "pub") and private (key "priv") main net versions
            test_net_ver (dict, optional) : dictionary containg public (key "pub") and private (key "priv") test net versions

        Returns (Bip32 object):
            Bip32 object
        """

        # De-serialize key
        key_deser = Bip32KeyDeserializer(key_str)
        key_deser.DeserializeKey(is_testnet, main_net_ver, test_net_ver)
        # Get key parts
        depth, fprint, child, chain, secret = key_deser.GetKeyParts()
        is_public = key_deser.IsPublic()

        # If private key, remove the first byte
        if not is_public:
            if secret[0] != 0:
                raise Bip32KeyError("Invalid extended key (wrong secret)")
            secret = secret[1:]
        # If public key, recover the complete key from the compressed one
        else:
            try:
                secret = ecdsa.VerifyingKey.from_string(secret, curve = SECP256k1)
            except:
                raise Bip32KeyError("Invalid extended public key")

        return Bip32(
            secret     = secret,
            chain      = chain,
            depth      = depth,
            index      = child,
            fprint     = fprint,
            is_public  = is_public,
            is_testnet = is_testnet)

    def __init__(self,
                 secret,
                 chain,
                 depth      = 0,
                 index      = 0,
                 fprint     = Bip32Const.MASTER_FINGERPRINT,
                 is_public  = False,
                 is_testnet = False):
        """ Construct class from secret and chain.

        Args:
            secret (bytes)              : source bytes to generate the keypair
            chain (bytes)               : 32-byte representation of the chain code
            depth (int, optional)       : child depth, parent increments its own by one when assigning this (default: 0)
            index (int, optional)       : child index (default: 0)
            fprint (bytes, optional)    : parent fingerprint (default: 0)
            is_public (bool, optional)  : if true, this keypair will only contain a public key and can only create a public key chain  (default: false)
            is_testnet (bool, optional) : true if test net, lfase if main net  (default: false)
        """

        if not is_public:
            self.m_key     = ecdsa.SigningKey.from_string(secret, curve = SECP256k1)
            self.m_ver_key = self.m_key.get_verifying_key()
        else:
            self.m_key     = None
            self.m_ver_key = secret

        self.m_is_public     = is_public
        self.m_chain         = chain
        self.m_depth         = depth
        self.m_index         = index
        self.m_parent_fprint = fprint
        self.m_is_testnet    = is_testnet

    def ChildKey(self, index):
        """ Create and return a child key of the current one at the specified index.
        The index shall be hardened using HardenIndex method to use the private derivation algorithm.
        Bip32KeyError is raised if the index results in an invalid key.

        Args:
            index (int) : index

        Returns (Bip32 object):
            Child key as a new Bip32 object
        """
        if not self.m_is_public:
            return self.__CkdPriv(index)
        else:
            return self.__CkdPub(index)

    def DerivePath(self, path):
        """ Derive children keys from the specified path.
        Bip32PathError is raised if the seed length is too short or the path is not valid.

        Args:
            path (str) : path

        Returns (Bip32 object):
            Bip32 object
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

        Returns (bool):
            True if public-only, false otherwise
        """
        return self.m_is_public

    def PrivateKeyBytes(self):
        """ Return private key bytes.
        Bip32KeyError is raised if internal key is public-only.

        Returns (bytes):
            Private key bytes
        """
        if self.m_is_public:
            raise Bip32KeyError("Public-only deterministic keys have no private half")
        else:
            return self.m_key.to_string()

    def PublicKey(self):
        """ Return the ECDSA public key object.

        Return (ecdsa.VerifyingKey):
            Public key object
        """
        return self.m_ver_key

    def PublicKeyBytes(self, compressed = True):
        """ Return public key bytes.

        Args:
            compressed (bool) : true for returning the key in compressed SEC1 format, false otherwise

        Returns (bytes):
            Public key bytes
        """
        return self.m_ver_key.to_string("compressed") if compressed else self.m_ver_key.to_string("uncompressed")[1:]

    def ExtendedPublicKey(self,
                          main_net_ver = Bip32Const.MAIN_NET_VER["pub"],
                          test_net_ver = Bip32Const.TEST_NET_VER["pub"]):
        """ Return extended public key encoded in Base58 format.

        Args:
            main_net_ver (bytes, optional) : main net version
            test_net_ver (bytes, optional) : test net version

        Returns (str):
            Extended public key in Base58 format
        """
        return Bip32KeySerializer(self).SerializePublicKey(main_net_ver, test_net_ver)

    def ExtendedPrivateKey(self,
                           main_net_ver = Bip32Const.MAIN_NET_VER["priv"],
                           test_net_ver = Bip32Const.TEST_NET_VER["priv"]):
        """ Return extended private key encoded in Base58 format.
        Bip32KeyError is raised if internal key is public-only.

        Args:
            main_net_ver (bytes, optional) : main net version
            test_net_ver (bytes, optional) : test net version

        Returns (str):
            Extended private key in Base58 format
        """
        if self.m_is_public:
            raise Bip32KeyError("Cannot export an extended private key from a public-only deterministic key")

        return Bip32KeySerializer(self).SerializePrivateKey(main_net_ver, test_net_ver)

    def IsTestNet(self):
        """ Get if test net.

        Returns (bool):
            True if test net, false otherwise
        """
        return self.m_is_testnet

    def Depth(self):
        """ Get current depth.

        Returns (int):
            Current depth
        """
        return self.m_depth

    def Index(self):
        """ Get current index.

        Returns (int):
            Current index
        """
        return self.m_index

    def Chain(self):
        """ Get current chain.

        Returns (bytes):
            Current chain
        """
        return self.m_chain

    def KeyIdentifier(self):
        """ Get key identifier.

        Returns (bytes):
            Key identifier bytes
        """
        return utils.Hash160(self.PublicKeyBytes())

    def FingerPrint(self):
        """ Get key fingerprint.

        Returns (bytes):
            Key fingerprint bytes
        """
        return self.KeyIdentifier()[:Bip32Const.FINGERPRINT_BYTE_LEN]

    def ParentFingerPrint(self):
        """ Get parent fingerprint.

        Returns (bytes):
            Parent fingerprint bytes
        """
        return self.m_parent_fprint

    def __CkdPriv(self, index):
        """ Create a child key of the specified index.
        Bip32KeyError is raised if the index results in an invalid key.

        Args:
            index (int) : index

        Returns:
            Bip32 object constructed with the child parameters
        """

        # Index as bytes
        index_bytes = index.to_bytes(4, "big")

        # Data to HMAC
        if Bip32Utils.IsHardenedIndex(index):
            data = b"\0" + self.m_key.to_string() + index_bytes
        else:
            data = self.PublicKeyBytes() + index_bytes

        # Compute HMAC halves
        i_l, i_r = self.__HmacHalves(data)

        # Construct new key material from i_l and current private key
        i_l_int = string_to_int(i_l)
        if i_l_int >= Bip32Const.CURVE_ORDER:
            raise Bip32KeyError("Computed private child key is not valid, very unlucky index")

        pvt_int = string_to_int(self.m_key.to_string())
        k_int = (i_l_int + pvt_int) % Bip32Const.CURVE_ORDER
        if k_int == 0:
            raise Bip32KeyError("Computed private child key is not valid, very unlucky index")

        secret = (b"\0"*32 + int_to_string(k_int))[-32:]

        # Construct and return a new Bip32 object
        return Bip32(secret     = secret,
                     chain      = i_r,
                     depth      = self.m_depth + 1,
                     index      = index,
                     fprint     = self.FingerPrint(),
                     is_public  = False,
                     is_testnet = self.m_is_testnet)

    def __CkdPub(self, index):
        """ Create a publicly derived child key of the specified index.
        Bip32KeyError is raised if the index is hardened or results in an invalid key.

        Args:
            index (int) : index

        Returns:
            Bip32 object constructed with the child parameters
        """

        # Check if index is hardened
        if Bip32Utils.IsHardenedIndex(index):
            raise Bip32KeyError("Public child derivation cannot be used to create a hardened child key")

        # Data to HMAC, same of CkdPriv() for public child key
        data = self.PublicKeyBytes() + index.to_bytes(4, "big")

        # Get HMAC of data
        i_l, i_r = self.__HmacHalves(data)

        # Construct curve point i_l*G+K
        i_l_int = string_to_int(i_l)
        if i_l_int >= Bip32Const.CURVE_ORDER:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index")

        point = i_l_int * generator_secp256k1 + self.m_ver_key.pubkey.point
        if point == Bip32Const.INFINITY:
            raise Bip32KeyError("Computed public child key is not valid, very unlucky index")

        # Retrieve public key based on curve point
        k_i = ecdsa.VerifyingKey.from_public_point(point, curve = SECP256k1)

        # Construct and return a new Bip32 object
        return Bip32(secret     = k_i,
                     chain      = i_r,
                     depth      = self.m_depth + 1,
                     index      = index,
                     fprint     = self.FingerPrint(),
                     is_public  = True,
                     is_testnet = self.m_is_testnet)

    def __HmacHalves(self, data_bytes):
        """ Calculate the HMAC-SHA512 of input data using the chain code as key and returns a tuple of the left and right halves of the HMAC.

        Args:
            data_bytes (bytes) : data bytes

        Returns (tuple):
            Left and right halves of the HMAC
        """

        # Use chain as HMAC key
        hmac = utils.HmacSha512(self.m_chain, data_bytes)
        return (hmac[:32], hmac[32:])
