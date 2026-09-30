#include <iostream>
#include "aes.hpp"

std::string ToHex(const std::string& data)
{
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
	std::string input = "115792089237316195423570985008687907853269984665640564039457584007913129639747";
	std::string secret = "1234567891234567";

	/*
	std::cout << "AES 256 - encryption \n Type your data: ";
	std::cin >> input;
	std::cout << "\n Pass secret: ";
	std::cin >> secret;
	*/

	AES aes;

	std::string cipher_text = aes.Encrypt(input, secret);



	std::cout << ToHex(cipher_text);
}