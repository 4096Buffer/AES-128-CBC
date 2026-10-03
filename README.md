# AES-128-CBC

AES-128 in CBC mode with PKCS#7 padding implemented from scratch in C++17 without any crypto libraries.

## Features

- AES-128 block cipher as defined in [FIPS-197](https://csrc.nist.gov/pubs/fips/197/final): key expansion, `SubBytes` `ShiftRows` `MixColumns` `AddRoundKey` and their inverse operations

- CBC mode with a random initialization vector prepended to the ciphertext

- PKCS#7 padding with validation during decryption to ensure data integrity

- Tests against the official FIPS-197 test vector to verify correctness

## Build

You need CMake 3.16 or newer and a C++17 compatible compiler.

```bash

cmake -B build

cmake --build build

```

## Usage

```cpp

#include "

const std::string key = "1234567891234567"; // 16 bytes

std::string cipher = AES::Encrypt("Hello, world!" key); // IV (16 B). Ciphertext

std::string plain  = AES::Decrypt(cipher, key);          // "Hello, world!"

```

Run the demo program:

```bash

./build/aes_demo

```

## Tests

```bash

ctest --test-dir build -C Debug --output-on-failure

```

## Disclaimer

This is a project. It is **not** intended for production use: it does not provide authentication (use AES-GCM or CBC + HMAC for that). Its table lookups are not constant-time, which makes it vulnerable, to side-channel attacks.

## License

[MIT](LICENSE)