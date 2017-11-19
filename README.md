### An ISO-C++17 header-only Keccak/SHA-3 implementation.

```
Performance for long messages on an Intel 8700K running at 4.7 GHz.
    cycles / byte = 4.7*10^9 / (Bandwidth * 1024^2)
        -> ~7.6 cycles / byte for SHAKE128
        -> ~9.5 cycles / byte for SHAKE256

Name            Bandwidth       NoOptTag
SHA3-256        475 MiB/s       29d4562a1e3bfdfe322b6fce6f065782
SHA3-512        256 MiB/s       96cbeb4de24f8432066fd1c89b6b4126
SHAKE-128       587 MiB/s       832aed26c0e08b41fa341747b7de85d3
SHAKE-256       470 MiB/s       28ed66da30aba0d270ed32bbacd4feff
```

To compile demo with gcc use
```
g++ -std=c++17 -pedantic -Wall -Wextra -O3 -march=native -o demo.exe demo.cpp
```
Also works with Visual Studio 2017. (Use /std:c++latest)
For clang, compile with -fno-slp-vectorize for best performance. Unfortunately clang's SLP vectorizer is a bit over motivated.

(Keyed)-Hashing, Single-Pass Authenticated Encryption & Cryptographically Secure Pseudo Random Number Generation - all based on a single implementation of the Keccak round function. (The authenticated encryption modes are highly experimental and should be treated as such.)

###### References
1. [NIST FIPS 202 / SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](http://dx.doi.org/10.6028/NIST.FIPS.202)
2. [sponge.noekeon.org](http://sponge.noekeon.org)
4. [keccak.noekeon.org](http://keccak.noekeon.org)
3. [Cryptographic sponge functions](http://sponge.noekeon.org/CSF-0.1.pdf)