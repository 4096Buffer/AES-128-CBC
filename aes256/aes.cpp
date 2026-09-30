#include "aes.hpp"

std::vector<Block> AES::GroupBlocks(std::string& data) {
	std::vector<Block> blocks;
	Block bytes{};
	
	std::cout << data << '\n';
	std::cout << "length: " << data.length() << '\n';

	int full_blocks = data.length() / 16;
	int last_i = 16 * (full_blocks + 1);
	size_t padding = 16 - (data.length() % 16);

	data.resize(last_i);

	char* first_ptr = data.data();

	for (size_t i = last_i - padding; i < last_i; ++i) {
		*(first_ptr + i) = padding;
	}
	
	size_t i = 0;
	
	while (i < data.length()) {
		char c{};

		for (size_t j = 0; j < 16; ++j) {
			c = *(first_ptr + i + j);
			bytes[j % 4][j / 4] = c;
		}

		blocks.push_back(bytes);
		bytes = {};

		i += 16;
	}

	for (const auto& b : blocks) {
		for (const auto& row : b) {
			for (auto el : row) {
				std::cout << static_cast<int>(el) << ' ';
			}
			std::cout << '\n';
		}
		std::cout << "##################\n";
	}

	return blocks;
}

void AES::AddRoundKey(Block& state, const Block& round_key) {
	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			state[row][col] ^= round_key[row][col];
		}
	}
}

void AES::SubBytes(Block& state) {
	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			state[row][col] = SBOX[state[row][col]];
		}
	}
}

void AES::MixColumns(Block& state) {
	for (size_t col = 0; col < 4; ++col) {
		unsigned char a0 = state[0][col];
		unsigned char a1 = state[1][col];
		unsigned char a2 = state[2][col];
		unsigned char a3 = state[3][col];

		state[0][col] = Mul2(a0) ^ Mul3(a1) ^ a2 ^ a3;
		state[1][col] = a0 ^ Mul2(a1) ^ Mul3(a2) ^ a3;
		state[2][col] = a0 ^ a1 ^ Mul2(a2) ^ Mul3(a3);
		state[3][col] = Mul3(a0) ^ a1 ^ a2 ^ Mul2(a3);
	}
}

// A B C D -> A B C D
// E F G H -> 
// I J K L



void AES::ShiftRows(Block& state) {
	for (size_t row = 0; row < 4; ++row) {
		unsigned char temp[4];

		for (size_t col = 0; col < 4; ++col) {
			temp[col] = state[row][col];
		}

		for (size_t col = 0; col < 4; ++col) {
			state[row][col] = temp[(col + row) % 4];
		}
	}
}

void AES::CreateRoundKeys(const std::string& secret, Block (&round_keys)[11]) {
	if (secret.size() != 16)
		throw std::runtime_error("AES-128 KEY must be 16 bytes!");

	Block key_matrix{};

	for (size_t i = 0; i < 16; ++i) {
		key_matrix[i % 4][i / 4] = static_cast<unsigned char>(secret[i]);
	}

	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			round_keys[0][row][col] = key_matrix[row][col];
		}
	}

	for (size_t round = 1; round <= 10; ++round) {
		unsigned char last_column[4] = {
			round_keys[round - 1][0][3],
			round_keys[round - 1][1][3],
			round_keys[round - 1][2][3],
			round_keys[round - 1][3][3],
		};

		//ROT WORD

		unsigned char first = last_column[0];
		last_column[0] = last_column[1];
		last_column[1] = last_column[2];
		last_column[2] = last_column[3];
		last_column[3] = first;

		//subword

		for (size_t i = 0; i < 4; ++i) {
			last_column[i] = SBOX[last_column[i]];
		}

		//RCON

		last_column[0] ^= RCON[round];

		for (size_t row = 0; row < 4; ++row) {
			round_keys[round][row][0] = round_keys[round - 1][row][0] ^ last_column[row];
		}

		for (size_t col = 1; col < 4; ++col) {
			for (size_t row = 0; row < 4; ++row) {
				round_keys[round][row][col] = round_keys[round - 1][row][col] ^ round_keys[round][row][col - 1];
			}
		}
	}
}

void AES::GenerateIV(Block& iv) {
	std::random_device rd;

	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			iv[row][col] = static_cast<unsigned char>(rd() & 0xFF);
		}
	}
}

void AES::CBCBlocks(std::vector<Block>& blocks, Block& iv, const Block(&round_keys)[11]) {
	GenerateIV(iv);

	if (blocks.empty())
		return;

	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			blocks[0][row][col] ^= iv[row][col];
		}
	}
	
	EncryptBlock(blocks[0], round_keys);

	for (size_t i = 1; i < blocks.size(); ++i) {

		for (size_t row = 0; row < 4; ++row) {
			for (size_t col = 0; col < 4; ++col) {
				blocks[i][row][col] ^= blocks[i-1][row][col];
			}
		}

		EncryptBlock(blocks[i], round_keys);
	}
}

void AES::EncryptBlock(Block& block, const Block(&round_keys)[11]) {
	AddRoundKey(block, round_keys[0]);

	for (size_t i = 1; i <= 10; ++i) { // 1-9 rounds
		SubBytes(block);
		ShiftRows(block);

		if (i < 10) {
			MixColumns(block);
		}

		AddRoundKey(block, round_keys[i]);
	}
}

std::string AES::Encrypt(std::string& raw, const std::string& secret) {
	std::vector<Block> blocks = GroupBlocks(raw);
	Block round_keys[11];
	Block iv{};

	CreateRoundKeys(secret, round_keys);
	CBCBlocks(blocks, iv, round_keys);

	std::string result;

	for (size_t i = 0; i < 16; ++i) {
		result.push_back(iv[i % 4][i / 4]);
	}

	for (const auto& block : blocks) {
		for (size_t i = 0; i < 16; ++i) {
			result.push_back(block[i % 4][i / 4]);
		}
	}

	return result;
}