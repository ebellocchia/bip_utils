## SLIP-0032 library

The SLIP-0032 library allows to serialize/deserialize keys as defined by [SLIP-0032](https://github.com/satoshilabs/slips/blob/master/slip-0032.md).

**Code example**

    import binascii
    from bip_utils import (
        Slip32PublicKeySerializer, Slip32PrivateKeySerializer, Slip32KeyDeserializer,
        Secp256k1PublicKey, Secp256k1PrivateKey
    )
    
    chain_code_bytes = binascii.unhexlify(b"47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
    # Serialize public key
    pub_key_bytes = binascii.unhexlify(b"035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")
    pub_key_ser = Slip32PublicKeySerializer.Serialize(
        Secp256k1PublicKey.FromBytes(pub_key_bytes),
        "m/0'/1",
        chain_code_bytes
    )
    print(pub_key_ser)
    
    # Serialize private key
    priv_key_bytes = binascii.unhexlify(b"edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
    priv_key_ser = Slip32PrivateKeySerializer.Serialize(
        Secp256k1PrivateKey.FromBytes(priv_key_bytes),
        "m/0'/1",
        chain_code_bytes
    )
    print(priv_key_ser)
    
    # Deserialize a key
    deser_key = Slip32KeyDeserializer.DeserializeKey(priv_key_ser)
    # Print results
    print(deser_key.KeyBytes())
    print(deser_key.Path().ToStr())
    print(deser_key.ChainCode().ToHex())
    print(deser_key.IsPublic())
