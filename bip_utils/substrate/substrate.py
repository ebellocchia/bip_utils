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


# Imports
from __future__ import annotations
import sr25519
from enum import Enum, auto, unique
from typing import Dict, Optional, Union
from bip_utils.conf import *
from bip_utils.substrate.substrate_ex import SubstrateKeyError
from bip_utils.substrate.substrate_keys import SubstratePublicKey, SubstratePrivateKey
from bip_utils.substrate.substrate_path import SubstratePathElem, SubstratePath, SubstratePathParser


@unique
class SubstrateCoins(Enum):
    """ Enumerative for supported Substrate coins. """

    ACALA = auto(),
    BIFROST = auto(),
    CHAINX = auto(),
    EDGEWARE = auto(),
    GENERIC = auto(),
    KARURA = auto(),
    KUSAMA = auto(),
    MOONBEAM = auto(),
    MOONRIVER = auto(),
    PHALA = auto(),
    PLASM = auto(),
    POLKADOT = auto(),
    SORA = auto(),
    STAFI = auto(),


class SubstrateConst:
    """ Class container for Substrate constants. """

    # Seed length in bytes
    SEED_BYTE_LEN: int = 32

    # Map from SubstrateCoins to configuration classes
    COIN_TO_CONF: Dict[SubstrateCoins, SubstrateCoinConf] = {
            SubstrateCoins.ACALA: SubstrateAcala,
            SubstrateCoins.BIFROST: SubstrateBifrost,
            SubstrateCoins.CHAINX: SubstrateChainX,
            SubstrateCoins.EDGEWARE: SubstrateEdgeware,
            SubstrateCoins.GENERIC: SubstrateGeneric,
            SubstrateCoins.KARURA: SubstrateKarura,
            SubstrateCoins.KUSAMA: SubstrateKusama,
            SubstrateCoins.MOONBEAM: SubstrateMoonbeam,
            SubstrateCoins.MOONRIVER: SubstrateMoonriver,
            SubstrateCoins.PHALA: SubstratePhala,
            SubstrateCoins.PLASM: SubstratePlasm,
            SubstrateCoins.POLKADOT: SubstratePolkadot,
            SubstrateCoins.SORA: SubstrateSora,
            SubstrateCoins.STAFI: SubstrateStafi,
        }


class Substrate:

    #
    # Construction methods
    #

    @classmethod
    def FromSeed(cls,
                 seed_bytes: bytes,
                 coin_type: SubstrateCoins) -> Substrate:
        """ Create a Substrate object from the specified seed.

        Args:
            seed_bytes (bytes)        : Seed bytes
            coin_type (SubstrateCoins): Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            ValueError: If the seed length is not valid
        """
        if not isinstance(coin_type, SubstrateCoins):
            raise TypeError("Coin is not an enumerative of SubstrateCoins")
        if len(seed_bytes) < SubstrateConst.SEED_BYTE_LEN:
            raise ValueError("Seed length is too small, it shall be at least %d bytes" % SubstrateConst.SEED_BYTE_LEN)

        pub_key_bytes, priv_key_bytes = sr25519.pair_from_seed(seed_bytes[:SubstrateConst.SEED_BYTE_LEN])
        return cls(priv_key_bytes=priv_key_bytes,
                   pub_key_bytes=pub_key_bytes,
                   path=SubstratePath([]),
                   coin_conf=SubstrateConst.COIN_TO_CONF[coin_type])

    @classmethod
    def FromSeedAndPath(cls,
                        seed_bytes: bytes,
                        path: Union[str, SubstratePath],
                        coin_type: SubstrateCoins) -> Substrate:
        """ Create a Substrate object from the specified seed and path.

        Args:
            seed_bytes (bytes)                : Seed bytes
            path (str or SubstratePath object): Path
            coin_type (SubstrateCoins)        : Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            ValueError: If the seed length is not valid
            SubstratePathError: If the path is not valid
        """
        substrate_ctx = cls.FromSeed(seed_bytes, coin_type)
        return substrate_ctx.DerivePath(path)

    @classmethod
    def FromPrivateKey(cls,
                       key_bytes: bytes,
                       coin_type: SubstrateCoins) -> Substrate:
        """ Create a Substrate object from the specified private key.

        Args:
            key_bytes (bytes)         : Key bytes
            coin_type (SubstrateCoins): Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            SubstrateKeyError: If the key is not valid
        """
        if not isinstance(coin_type, SubstrateCoins):
            raise TypeError("Coin is not an enumerative of SubstrateCoins")

        return cls(priv_key_bytes=key_bytes,
                   pub_key_bytes=None,
                   path=SubstratePath([]),
                   coin_conf=SubstrateConst.COIN_TO_CONF[coin_type])

    @classmethod
    def FromPublicKey(cls,
                      key_bytes: bytes,
                      coin_type: SubstrateCoins) -> Substrate:
        """ Create a Substrate object from the specified public key.

        Args:
            key_bytes (bytes)         : Key bytes
            coin_type (SubstrateCoins): Coin type

        Returns:
            Substrate object: Substrate object

        Raises:
            TypeError: If coin_type is not of SubstrateCoins enum
            SubstrateKeyError: If the key is not valid
        """
        if not isinstance(coin_type, SubstrateCoins):
            raise TypeError("Coin is not an enumerative of SubstrateCoins")

        return cls(priv_key_bytes=None,
                   pub_key_bytes=key_bytes,
                   path=SubstratePath([]),
                   coin_conf=SubstrateConst.COIN_TO_CONF[coin_type])

    #
    # Public methods
    #

    def __init__(self,
                 priv_key_bytes: Optional[bytes],
                 pub_key_bytes: Optional[bytes],
                 path: SubstratePath,
                 coin_conf: SubstrateCoinConf) -> None:
        """ Construct class from keys.

        Args:
            priv_key_bytes (bytes)              : Private key bytes, if None a public-only object will be created
            pub_key_bytes (bytes)               : Public key bytes
            path (SubstratePath object)         : Path
            coin_conf (SubstrateCoinConf object): SubstrateCoinConf object

        Raises:
            SubstrateKeyError: If one of the key is not valid
        """
        if priv_key_bytes is not None:
            self.m_priv_key = SubstratePrivateKey.FromBytes(priv_key_bytes, coin_conf)
            self.m_pub_key = (SubstratePublicKey.FromBytes(pub_key_bytes, coin_conf)
                              if pub_key_bytes is not None
                              else self.m_priv_key.PublicKey())
        else:
            self.m_priv_key = None
            self.m_pub_key = SubstratePublicKey.FromBytes(pub_key_bytes, coin_conf)

        self.m_path = path
        self.m_coin_conf = coin_conf

    def ChildKey(self,
                 path_elem: Union[str, SubstratePathElem]) -> Substrate:
        """ Create and return a child key of the current one with the specified path element.

        Args:
            path_elem (str or SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstrateKeyError: If the index results in invalid keys
        """
        if isinstance(path_elem, str):
            path_elem = SubstratePathElem(path_elem)

        return self.__CkdPriv(path_elem) if not self.IsPublicOnly() else self.__CkdPub(path_elem)

    def DerivePath(self,
                   path: Union[str, SubstratePath]) -> Substrate:
        """ Derive children keys from the specified path.

        Args:
            path (str or SubstratePath object): Path

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstratePathError: If the path is not valid
        """
        if isinstance(path, str):
            path = SubstratePathParser.Parse(path)

        substrate_obj = self
        # Derive children keys
        for path_elem in path:
            substrate_obj = substrate_obj.ChildKey(path_elem)

        return substrate_obj

    def ConvertToPublic(self) -> None:
        """ Convert a private Substrate object into a public one. """
        self.m_priv_key = None

    def IsPublicOnly(self) -> bool:
        """ Get if it's public-only.

        Returns:
            bool: True if public-only, false otherwise
        """
        return self.m_priv_key is None

    def CoinConf(self) -> SubstrateCoinConf:
        """ Return coin configuration.

        Returns:
            SubstrateCoinConf object: SubstrateCoinConf object
        """
        return self.m_coin_conf

    def Path(self) -> SubstratePath:
        """ Return path.

        Returns:
            SubstratePath object: SubstratePath object
        """
        return self.m_path

    def PrivateKey(self) -> SubstratePrivateKey:
        """ Return private key object.

        Returns:
            SubstratePrivateKey object: SubstratePrivateKey object

        Raises:
            SubstrateKeyError: If internal key is public-only
        """
        if self.IsPublicOnly():
            raise SubstrateKeyError("Public-only deterministic keys have no private half")
        return self.m_priv_key

    def PublicKey(self) -> SubstratePublicKey:
        """ Return public key object.

        Returns:
            SubstratePublicKey object: SubstratePublicKey object
        """
        return self.m_pub_key

    #
    # Private methods
    #

    def __CkdPriv(self,
                  path_elem: SubstratePathElem) -> Substrate:
        """ Create a child key of the specified path element using private derivation.

        Args:
            path_elem (SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object
        """
        ex_key_pair = (path_elem.ChainCode(), self.m_pub_key.RawCompressed().ToBytes(), self.m_priv_key.Raw().ToBytes())

        if path_elem.IsHard():
            _, pub_key_bytes, priv_key_bytes = sr25519.hard_derive_keypair(ex_key_pair, b"")
        else:
            _, pub_key_bytes, priv_key_bytes = sr25519.derive_keypair(ex_key_pair, b"")

        return Substrate(priv_key_bytes=priv_key_bytes,
                         pub_key_bytes=pub_key_bytes,
                         path=self.m_path.AddElem(path_elem),
                         coin_conf=self.m_coin_conf)

    def __CkdPub(self,
                 path_elem: SubstratePathElem) -> Substrate:
        """ Create a child key of the specified index using public derivation.

        Args:
            path_elem (SubstratePathElem object): Path element

        Returns:
            Substrate object: Substrate object

        Raises:
            SubstrateKeyError: If the path element is hard
        """
        if path_elem.IsHard():
            raise SubstrateKeyError("Public child derivation cannot be used to create a hardened child key")

        ex_key_pair = (path_elem.ChainCode(), self.m_pub_key.RawCompressed().ToBytes())

        _, pub_key_bytes = sr25519.derive_pubkey(ex_key_pair, b"")

        return Substrate(priv_key_bytes=None,
                         pub_key_bytes=pub_key_bytes,
                         path=self.m_path.AddElem(path_elem),
                         coin_conf=self.m_coin_conf)
