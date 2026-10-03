#include "aes.hpp"
#include <cstdio>
#include <string>

static int failures = 0;

#define CHECK(cond) \
    do { if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static std::string FromHex(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

static Block ToBlock(const std::string& bytes) {
    Block b{};
    for (size_t i = 0; i < 16; ++i) b[i % 4][i / 4] = static_cast<unsigned char>(bytes[i]);
    return b;
}

void TestFips197Vector() {
    RoundKeys keys{};
    AES::CreateRoundKeys(FromHex("000102030405060708090a0b0c0d0e0f"), keys);

    Block block = ToBlock(FromHex("00112233445566778899aabbccddeeff"));
    AES::EncryptBlock(block, keys);
    CHECK(block == ToBlock(FromHex("69c4e0d86a7b0430d8cdb78070b4c55a")));

    AES::DecryptBlock(block, keys);
    CHECK(block == ToBlock(FromHex("00112233445566778899aabbccddeeff")));
}

void TestRoundTrip() {
    const std::string key = "1234567891234567";
    for (size_t len : {0, 1, 15, 16, 17, 31, 32, 100}) {
        std::string plain(len, 'x');
        CHECK(AES::Decrypt(AES::Encrypt(plain, key), key) == plain);
    }
}

void TestWrongKeyLength() {
    bool thrown = false;
    try { AES::Encrypt("abc", "short"); } catch (const std::runtime_error&) { thrown = true; }
    CHECK(thrown);
}

int main() {
    TestFips197Vector();
    TestRoundTrip();
    TestWrongKeyLength();

    if (failures == 0) std::printf("All tests passed\n");
    return failures == 0 ? 0 : 1;
}