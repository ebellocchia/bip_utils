## Bech32

The bech32 library allows encoding/decoding in:
- bech32 and bech32m
- Segwit
- Bitcoin Cash bech32

`Bech32ChecksumError` is raised if checksum verification fails.\
`ValueError` is raised in case of other errors.

**Code example**

    import binascii
    from bip_utils import (
        Bech32Decoder, Bech32Encoder, BchBech32Encoder, BchBech32Decoder, SegwitBech32Decoder, SegwitBech32Encoder
    )

    data_bytes = binascii.unhexlify(b'9c90f934ea51fa0f6504177043e0908da6929983')

    # Encode with bech32
    enc = Bech32Encoder.Encode("cosmos", data_bytes)
    # Decode with bech32
    dec = Bech32Decoder.Decode("cosmos", enc)

    # Encode with segwit bech32 (witness version equal to 0)
    enc = SegwitBech32Encoder.Encode("bc", 0, data_bytes)
    # Encode with segwit bech32m (witness version equal to 1)
    enc = SegwitBech32Encoder.Encode("bc", 1, data_bytes)
    # Decode with segwit (bech32 or bech32m automatically detected)
    wit_ver, wit_prog = SegwitBech32Decoder.Decode("bc", enc)

    # Encode with BCH bech32
    enc = BchBech32Encoder.Encode("bitcoincash", b"\x00", data_bytes)
    # Decode with BCH bech32
    net_ver, dec = BchBech32Decoder.Decode("bitcoincash", enc)
