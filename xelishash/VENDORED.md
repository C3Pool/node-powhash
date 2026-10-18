xelis-hash v3 for XELIS share verification:
- xelis_hash_v3.c: github.com/xelis-project/xelis-hash @ f48262b (MIT, LICENSE-xelis-hash)
- ChaCha20-SIMD/: from the same repository (MIT, ChaCha20-SIMD/LICENSE)
- BLAKE3/c: github.com/BLAKE3-team/BLAKE3 tag 1.5.4 @ 95e42b8, C sources without the
  assembly files (Apache-2.0, BLAKE3/LICENSE_A2)
x86-64 only: the hash uses AES-NI and x86-64 inline assembly.
