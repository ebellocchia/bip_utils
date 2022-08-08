## Base58

The base58 library allows encoding/decoding in base58 format, including the one used by Monero.\
It supports both normal encode/decode and check_encode/check_decode with Bitcoin and Ripple alphabets.\
If not specified, the Bitcoin one will be used by default.

Alphabet enumeratives:

|Alphabet|Enum|
|---|---|
|Bitcoin|`Base58Alphabets.BITCOIN`|
|Ripple|`Base58Alphabets.RIPPLE`|

`ValueError` is raised in case of errors.

**Code example**

    import binascii
    from bip_utils import Base58Alphabets, Base58Decoder, Base58Encoder, Base58XmrDecoder, Base58XmrEncoder

    data_bytes = binascii.unhexlify(b"636363")

    # Normal encode
    enc = Base58Encoder.Encode(data_bytes)
    # Check encode
    chk_enc = Base58Encoder.CheckEncode(data_bytes)

    # Normal decode
    dec = Base58Decoder.Decode(enc)
    # Check decode
    # Base58ChecksumError is raised if checksum verification fails
    # ValueError is raised in case of encoding errors
    chk_dec = Base58Decoder.CheckDecode(chk_enc)

    # Same as before with Ripple alphabet
    enc = Base58Encoder.Encode(data_bytes, Base58Alphabets.RIPPLE)
    chk_enc = Base58Encoder.CheckEncode(data_bytes, Base58Alphabets.RIPPLE)
    dec = Base58Decoder.Decode(enc, Base58Alphabets.RIPPLE)
    chk_dec = Base58Decoder.CheckDecode(chk_enc, Base58Alphabets.RIPPLE)

    # Encode/Decode using Monero version
    enc = Base58XmrEncoder.Encode(data_bytes)
    dec = Base58XmrDecoder.Decode(enc)
