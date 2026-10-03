# AES-128-CBC

AES-128 in CBC mode with PKCS#7 padding, implemented from scratch in C++17 — no external crypto libraries.

## Features

- Full AES-128 block cipher per [FIPS-197](https://csrc.nist.gov/pubs/fips/197/final): key expansion, `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey` and their inverses
- CBC mode with a random IV prepended to the ciphertext
- PKCS#7 padding with validation on decrypt
- Tests against the official FIPS-197 test vector

## Build

Requires CMake 3.16+ and a C++17 compiler.

```bash
cmake -B build
cmake --build build
```

## Usage

```cpp
#include "aes.hpp"

const std::string key = "1234567891234567"; // 16 bytes

std::string cipher = AES::Encrypt("Hello, world!", key); // IV (16 B) + ciphertext
std::string plain  = AES::Decrypt(cipher, key);          // "Hello, world!"
```

Run the demo:

```bash
./build/aes_demo
```

## Tests

```bash
ctest --test-dir build -C Debug --output-on-failure
```

## Disclaimer

This is an educational project. It is **not** intended for production use: it provides no authentication (use AES-GCM or CBC + HMAC for that) and its table lookups are not constant-time.

## License

[MIT](LICENSE)
