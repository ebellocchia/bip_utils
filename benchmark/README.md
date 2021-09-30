# Introduction

As you've probably already guessed, I developed this library focusing on functionalities rather than speed.\
In my mind, the main purpose of the library is to be used by single-coin or multi-coin wallets (or similar applications) to generate and derive keys starting from the mnemonic, so that the developers can focus on more important stuff.\
Therefore, it doesn't require to be super-fast, since a user usually only needs to generate some addresses once in a while (most of the time only one or two in total).

Anyway, it's always useful to have a small benchmark to check if the last changes slowed down the code or something can be optimized.\
For example, I added the cache mechanism after realizing that recomputing stuff in some getter methods was consuming a huge amount of time.\
So, for me the purpose of this benchmark is only to have an idea of performance changes when I update the code.

As you can imagine, the slowest "coins" are the ones whose elliptic curve library is implemented in pure python, i.e. Monero and ECDSA-based coins.\
However, even in this case it only takes 1 or 2 milliseconds to derive a private/public key, so it's not an issue for a wallet (of course, a C/C++ based library is much faster).

# Running the benchmark

Just set the benchmark variables by editing the *TestsConf* class at the beginning of *benchmark.py* and run the file from this folder (after having installed bip_utils, of course):

    python ./benchmark.py

You probably just want to modify the *BENCHMARK_TEST_TYPE* variable, which can assume one of the following values:

|Type|Description|
|---|---|
|TestTypes.SECP256K1|Test coins based on secp256k1 curve|
|TestTypes.NIST256P1|Test coins based on nist256p1 curve|
|TestTypes.ED25519|Test coins based on ed25519 curve|
|TestTypes.ED25519_BLAKE2B|Test coins based on ed25519-blake2b curve|
|TestTypes.SUBSTRATE|Test coins based on sr25519 curve (substrate library)|
|TestTypes.MONERO|Test Monero|

It's suggested to close all applications to run the benchmark, so that they do not interfere with the timings.\
The structure of the tests are all the same except for Substrate and Monero, since their way to derive keys is different from BIP44.
