## An experimental ISO-C++14^1 header-only Keccak/SHA-3 implementation.

### (Keyed)-Hashing, Single-Pass Authenticated Encryption & Cryptographically Secure Pseudo Random Number Generation - all based on a single implementation of the Keccak round function.

#### Resources: 
1. [NIST FIPS 202 / SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](http://dx.doi.org/10.6028/NIST.FIPS.202)
2. [sponge.noekeon.org](http://sponge.noekeon.org), [keccak.noekeon.org](http://keccak.noekeon.org)
3. [Cryptographic sponge functions](http://sponge.noekeon.org/CSF-0.1.pdf)

Performance for long messages on an Intel 3570k running at 4.2GH. Compiler: VS 2015
cycles / byte = 4200000000 / (Bandwidth * 1024 * 1024)
 -> ~13 cycles/byte for SHAKE128

```
Name				Time		Bandwidth		Hex

SHA3-256			1025 ms		250 MiB/s		aa2cd13c77453227
SHA3-512			1930 ms		133 MiB/s		68beb4061162c905
SHAKE128			832 ms		308 MiB/s		17bbd7ab3ca76c98
SHAKE256			1024 ms		250 MiB/s		7dbc83659035340d
Auth. 128-bit encryption	857 ms		299 MiB/s		dfcf7627921e7137
Auth. 256-bit encryption	1066 ms		240 MiB/s		4e4b1b67fbbac077
CSPRNG 128-bit			856 ms		299 MiB/s		0350ba253962eb6a
```

To compile demo with gcc: g++ -Wall -Wextra -pedantic -O4 -std=c++14 -o demo.exe demo.cpp

^1 #pragma once is used.