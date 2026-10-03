#include <iostream>
#include "aes.hpp"

std::string ToHex(const std::string& data) {
	static const char* hex = "0123456789ABCDEF";
	
	std::string out;
	out.reserve(data.size() * 2);

	for (unsigned char byte : data) {
		out.push_back(hex[byte >> 4]);
		out.push_back(hex[byte & 0x0F]);
	}

	return out;
}

int main() {
	std::string input;
	std::string secret = "1234567891234567"; // 16 bytes EXAMPLE KEY

	std::cout << "AES 256 - encryption \n Type your data: ";
	std::cin >> input;

	std::string cipher_text = AES::Encrypt(input, secret);

	std::cout << "ENCRYPTED TEXT CONVERTED TO HEX: " << ToHex(cipher_text) << '\n';
	
	std::cout << "DECRYPTED PLAIN TEXT: " << AES::Decrypt(cipher_text, secret) << '\n';
}