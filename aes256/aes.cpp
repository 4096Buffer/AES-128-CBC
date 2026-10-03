#include "aes.hpp"

std::vector<Block> AES::GroupBlocks(std::string& data, bool add_padding) {
	std::vector<Block> blocks;
	Block bytes{};

	if (!add_padding && data.size() % 16 != 0) {
		throw std::runtime_error("Ciphertext length must be multiple of 16 bytes!");
	}

	if (add_padding) {
		int full_blocks = data.length() / 16;
		int last_i = 16 * (full_blocks + 1);
		size_t padding = 16 - (data.length() % 16);

		data.resize(last_i);

		for (size_t i = last_i - padding; i < last_i; ++i) {
			data[i] = padding;
		}
	}
	
	size_t i = 0;
	
	while (i < data.length()) {
		char c{};

		for (size_t j = 0; j < 16; ++j) {
			c = data[i + j];
			bytes[j % 4][j / 4] = c;
		}

		blocks.push_back(bytes);
		bytes = {};

		i += 16;
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

void AES::InvShiftRows(Block& state) {
	for (size_t row = 0; row < 4; ++row) {
		unsigned char temp[4];

		for (size_t col = 0; col < 4; ++col) {
			temp[col] = state[row][col];
		}

		for (size_t col = 0; col < 4; ++col) {
			state[row][col] = temp[(col - row + 4) % 4];
		}
	}
}

void AES::InvSubBytes(Block& state) {

	for (size_t row = 0; row < 4; ++row) {
		for (size_t col = 0; col < 4; ++col) {
			state[row][col] = INV_SBOX[state[row][col]];
		}
	}
}

void AES::InvMixColumns(Block& state) {
	for (size_t col = 0; col < 4; ++col) {
		unsigned char a0 = state[0][col];
		unsigned char a1 = state[1][col];
		unsigned char a2 = state[2][col];
		unsigned char a3 = state[3][col];

		state[0][col] = Mul14(a0) ^ Mul11(a1) ^ Mul13(a2) ^ Mul9(a3);
		state[1][col] = Mul9(a0) ^ Mul14(a1) ^ Mul11(a2) ^ Mul13(a3);
		state[2][col] = Mul13(a0) ^ Mul9(a1) ^ Mul14(a2) ^ Mul11(a3);
		state[3][col] = Mul11(a0) ^ Mul13(a1) ^ Mul9(a2) ^ Mul14(a3);
	}
}

void AES::CreateRoundKeys(const std::string& secret, RoundKeys& round_keys) {
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

		unsigned char first = last_column[0];
		last_column[0] = last_column[1];
		last_column[1] = last_column[2];
		last_column[2] = last_column[3];
		last_column[3] = first;

		for (size_t i = 0; i < 4; ++i) {
			last_column[i] = SBOX[last_column[i]];
		}

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

void AES::EncryptCBC(std::vector<Block>& blocks, Block& iv, const RoundKeys& round_keys) {
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

void AES::DecryptCBC(std::vector<Block>& blocks, Block iv, const RoundKeys& round_keys) {
	if (blocks.empty()) return;

	Block previous = iv;

	for (auto& block : blocks) {
		Block current_cipher{};

		for (size_t row = 0; row < 4; ++row) {
			for (size_t col = 0; col < 4; ++col) {
				current_cipher[row][col] = block[row][col];
			}
		}

		DecryptBlock(block, round_keys);

		for (size_t row = 0; row < 4; ++row) {
			for (size_t col = 0; col < 4; ++col) {
				block[row][col] ^= previous[row][col];
			}
		}

		for (size_t row = 0; row < 4; ++row) {
			for (size_t col = 0; col < 4; ++col) {
				previous[row][col] = current_cipher[row][col];
			}
		}
	}
}

void AES::EncryptBlock(Block& block, const RoundKeys& round_keys) {
	AddRoundKey(block, round_keys[0]);

	for (size_t i = 1; i <= 10; ++i) { 
		SubBytes(block);
		ShiftRows(block);

		if (i < 10) {
			MixColumns(block);
		}

		AddRoundKey(block, round_keys[i]);
	}
}

void AES::DecryptBlock(Block& block, const RoundKeys& round_keys) {
	AddRoundKey(block, round_keys[10]);

	for (int round = 9; round >= 1; --round) {
		InvShiftRows(block);
		InvSubBytes(block);
		AddRoundKey(block, round_keys[round]);
		InvMixColumns(block);
	}

	InvShiftRows(block);
	InvSubBytes(block);
	AddRoundKey(block, round_keys[0]);
}

std::string AES::Decrypt(std::string encrypted, const std::string& secret) {
	if (encrypted.size() < 32)
		throw std::runtime_error("Invalid encrypted cypher text");

	Block iv{};
	RoundKeys round_keys{};

	for (size_t i = 0; i < 16; ++i) {
		iv[i % 4][i / 4] = encrypted[i];
	}

	std::string data = encrypted.erase(0, 16);
	std::vector<Block> blocks = GroupBlocks(data, false);

	CreateRoundKeys(secret, round_keys);
	DecryptCBC(blocks, iv, round_keys);

	std::string result;

	for (const auto& block : blocks) {
		for (size_t i = 0; i < 16; ++i) {
			result.push_back(block[i % 4][i / 4]);
		}
	}

	size_t padding = static_cast<unsigned char>(result.back());

	if (padding == 0 || padding > 16 || padding > result.size())
		throw std::runtime_error("Invalid PKCS#7 padding!");

	for (size_t i = 0; i < padding; ++i) {
		if (static_cast<unsigned char>(result[result.size() - 1 - i]) != padding)
			throw std::runtime_error("Invalid PKCS#7 padding");
	}

	result.resize(result.size() - padding);

	return result;
}

std::string AES::Encrypt(std::string raw, const std::string& secret) {
	std::vector<Block> blocks = GroupBlocks(raw);
	RoundKeys round_keys{};
	Block iv{};

	CreateRoundKeys(secret, round_keys);
	EncryptCBC(blocks, iv, round_keys);

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