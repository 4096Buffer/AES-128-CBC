#include <iostream>
#include "aes.hpp"

int main() {
	std::string input = "115792089237316195423570985008687907853269984665640564039457584007913129639747";
	std::string secret = "1234";

	/*
	std::cout << "AES 256 - encryption \n Type your data: ";
	std::cin >> input;
	std::cout << "\n Pass secret: ";
	std::cin >> secret;
	*/

	AES aes;

	aes.Encrypt(input, secret);
}