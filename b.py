import binascii
import cbor2
import hashlib
from nacl import bindings, encoding
from bip_utils import *
from bip_utils.bip.bip32.bip32_base import Bip32Base, Bip32BaseUtils
from bip_utils.ecc.ed25519.lib import ed25519_lib

p = Ed25519Point.FromBytes(binascii.unhexlify(b"7d5ea03ab150169176f66df6f6f67afe70b4d9e8b06fa6b46cd74bab1ca5e75c"))
print(p.Raw().ToHex())
print(p.RawEncoded().ToHex())
print(binascii.hexlify(ed25519_lib.point_encode(p.Raw().ToBytes())).decode())
p = 2 * p
print(p.X())
print(p.Y())
print("")


k = binascii.unhexlify(b"1075ab5e3fcedcb69eef77974b314cc0cbc163c01a0c354989dc70b8789a194fb52396acaa97135c2f2f042e4181da5fbe92b8350d00055bee42eccf3088fd24")
b = bindings.crypto_scalarmult_ed25519_base_noclamp(k[:32])
print(binascii.hexlify(b))
print("")

b = BytesUtils.ToInteger(k[:32], endianness="little") * Ed25519.Generator()
print(Ed25519PublicKey.FromPoint(b).RawCompressed().ToHex())
print("")

p1 = Ed25519PublicKey.FromPoint(Ed25519.Generator()).Point()
p2 = Ed25519PrivateKey.FromBytes(k[:32]).PublicKey().Point()
p3 = p1 + p2

print(p3.Raw().ToHex())
print(Ed25519PublicKey.FromPoint(p3).RawCompressed().ToHex())
print(encoding.RawEncoder.encode(p3.Raw().ToHex()))
print("")

if not bindings.crypto_core_ed25519_is_valid_point(binascii.unhexlify(b"dbfe097cbed0f8f10d8980e51c92f29aaea5b69e4e4fd243f41bedb3f73b8756")):
    raise ValueError("Invalid public key bytes")


p4 = bindings.crypto_core_ed25519_add(Ed25519PublicKey.FromPoint(p1).RawCompressed().ToBytes()[1:],
                                      Ed25519PublicKey.FromPoint(p2).RawCompressed().ToBytes()[1:])
print(binascii.hexlify(p4))
print("")



#seed_bytes = binascii.unhexlify("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
seed_bytes = binascii.unhexlify("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

bip32 = Bip32Ed25519Kholaw.FromSeed(seed_bytes).DerivePath("m/0/2147483647'/1/2147483646'/2")
print(bip32.PublicKey().ToExtended())
print(bip32.PrivateKey().ToExtended())
print(bip32.PublicKey().RawCompressed().ToHex())
print(bip32.PrivateKey().Raw().ToHex())
print(bip32.ChainCode().ToHex())
print(bip32.ParentFingerPrint().ToHex())
print("")
print("")

class CardanoByron(Bip32Ed25519Kholaw):
    @classmethod
    def _FromSeed(cls,
                  seed_bytes: bytes,
                  key_net_ver: Bip32KeyNetVersions) -> Bip32Base:
        priv_key = cls._hashRep(seed_bytes, 1)

        return cls(priv_key=priv_key[:64],
                   pub_key=None,
                   chain_code=Bip32ChainCode(priv_key[64:]),
                   curve_type=cls.CurveType(),
                   key_net_ver=key_net_ver)

    @classmethod
    def _hashRep(cls, key, i):
        #key = cbor2.dumps(key)
        il, ir = Bip32BaseUtils.HmacSha512Halves(key, b"Root Seed Chain " + IntegerUtils.ToBytes(i))
        prv = cls._TweakMasterKeyBits(CryptoUtils.Sha512(il))

        if BitUtils.AreBitsSet(prv[31], 0x20):
            return cls._hashRep(key, i + 1)
        return prv + ir


class CardanoIcarus(Bip32Ed25519Kholaw):
    @classmethod
    def _FromSeed(cls,
                  entropy_bytes: bytes,
                  key_net_ver: Bip32KeyNetVersions) -> Bip32Base:
        seed_bytes = CryptoUtils.Pbkdf2HmacSha512("",
                                                  entropy_bytes,
                                                  4096,
                                                  96)
        # Tweak key bytes
        seed_bytes = cls._TweakMasterKeyBits(seed_bytes)

        return cls(priv_key=seed_bytes[:64],
                   pub_key=None,
                   chain_code=Bip32ChainCode(seed_bytes[64:]),
                   curve_type=cls.CurveType(),
                   key_net_ver=key_net_ver)


def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()


def hash_data(v):
    return hash_serialized(cbor2.dumps(v))

mnemonic = "make song exile crawl machine hip pear busy minimum roast bullet venue catalog wagon trial"
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
entropy_bytes = Bip39MnemonicDecoder().Decode(mnemonic)
print(binascii.hexlify(entropy_bytes))
print(binascii.hexlify(hash_data(entropy_bytes)))

c = CardanoByron.FromSeed(entropy_bytes).DerivePath("m/0'/0'")
print("")
print("exprv: " + c.PrivateKey().Raw().ToHex())
print("expub: " + c.PublicKey().RawCompressed().ToHex()[2:] + c.ChainCode().ToHex())
print("expnt: " + c.PublicKey().Point().Raw().ToHex())
