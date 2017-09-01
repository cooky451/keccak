#### An ISO-C++14 header-only Keccak/SHA-3 implementation.

###### (Keyed)-Hashing, Single-Pass Authenticated Encryption & Cryptographically Secure Pseudo Random Number Generation - all based on a single implementation of the Keccak round function. (The authenticated encryption modes are highly experimental and should be treated as such.)

```
Performance for long messages on an Intel 3570k running at 4.2GH.
    cycles / byte = 4200000000 / (Bandwidth * 1024 * 1024)
        -> ~12.5 cycles/byte for SHAKE128

Name                            Time            Bandwidth               Hex

SHA3-256                        979 ms          262 MiB/s               aa2cd13c77453227
SHA3-512                        1825 ms         140 MiB/s               68beb4061162c905
SHAKE128                        796 ms          322 MiB/s               17bbd7ab3ca76c98
SHAKE256                        978 ms          262 MiB/s               7dbc83659035340d
Auth. 128-bit encryption        745 ms          344 MiB/s               2560139c698af784
Auth. 256-bit encryption        916 ms          280 MiB/s               6f4cba861dbd8173
CSPRNG 128-bit                  794 ms          323 MiB/s               17b38d3cab452a17
```

To compile demo with gcc use
```
g++ -Wall -Wextra -pedantic -O3 -std=c++14 -o demo.exe demo.cpp
```
Also works with Visual Studio 2015/2017 and clang.

###### References
1. [NIST FIPS 202 / SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](http://dx.doi.org/10.6028/NIST.FIPS.202)
2. [sponge.noekeon.org](http://sponge.noekeon.org)
4. [keccak.noekeon.org](http://keccak.noekeon.org)
3. [Cryptographic sponge functions](http://sponge.noekeon.org/CSF-0.1.pdf)