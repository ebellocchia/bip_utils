## Solana SPL tokens

The SPL token library allows generating token account addresses for Solana SPL tokens.

**Code example**

    import binascii
    from bip_utils import Bip44, Bip44Coins, SplToken
    
    # Derive Solana private key
    seed_bytes = binascii.unhexlify(b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA).DeriveDefaultPath()
    
    # Get address for USDC token
    usdc_addr = SplToken.GetAssociatedTokenAddress(bip44_ctx.PublicKey().ToAddress(),
                                                   "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    print(usdc_addr)
    # Get address for Serum token
    srm_addr = SplToken.GetAssociatedTokenAddress(bip44_ctx.PublicKey().ToAddress(),
                                                  "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt")
    print(srm_addr)
