#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cmath>
#include <bit>
#include <iostream>
#include <streambuf>

namespace sha256 {

// anonymous implementation namespace for helper constants/functions
namespace {

constexpr std::array<uint32_t, 8> initial_hash {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

constexpr std::array<uint32_t, 64> K256 {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

// logical functions
constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
constexpr uint32_t sigma0(uint32_t x) {
    return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
}
constexpr uint32_t sigma1(uint32_t x) {
    return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
}
constexpr uint32_t s0(uint32_t x) {
    return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3);
}
constexpr uint32_t s1(uint32_t x) {
    return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10);
}


// preprocess input string and return padded blocks for the hashing algorithm
std::vector<std::array<uint32_t, 64>> preprocess(const std::string& input) {
    std::vector<uint8_t> data(input.begin(), input.end());
    auto block_num = std::ceil((data.size() * 8. + 65) / 512);
    std::vector<std::array<uint32_t, 64>> blocks(block_num);

    // pad 0x80 at the end of message and pad length to multiple of 4 for easier endian conversion
    data.push_back(0x80);
    if(data.size() % 4) {
        auto left = 4 - (data.size() % 4);
        for(size_t i = 0; i < left; i++)
            data.push_back(0);
    }

    // split data into blocks of 512 bits (64 bytes are data, 192 bytes are for computation)
    for(size_t i = 0, idx = 0; i < block_num; i++) {
        for(size_t j = 0; j < 16 && idx < data.size(); j++, idx += 4) {
            if constexpr(std::endian::native == std::endian::little) {
                blocks[i][j] = (data[idx + 3] << 0) | (data[idx + 2] << 8) | (data[idx + 1] << 16) | (data[idx + 0] << 24);
            } else {
                blocks[i][j] = (data[idx + 0] << 0) | (data[idx + 1] << 8) | (data[idx + 2] << 16) | (data[idx + 3] << 24);
            }
        }
    }

    // write message length at the end
    uint64_t l = input.length() * 8ul;
    if constexpr(std::endian::native == std::endian::little) {
        blocks.back()[14] = (l >> 32) & 0xffff'ffff;
        blocks.back()[15] = l & 0xffff'ffff;
    } else {
        blocks.back()[15] = (l >> 32) & 0xffff'ffff;
        blocks.back()[14] = l & 0xffff'ffff;
    }

    return blocks;
}

std::array<uint32_t, 8> one_pass_hash(std::array<uint32_t, 64>& data, std::array<uint32_t, 8> state) {
    // prepare the message schedule W
    for(size_t i = 16; i < 64; i ++) {
        data[i] = s1(data[i - 2]) + data[i - 7] + s0(data[i - 15]) + data[i - 16];
    }

    // compute the intermediate hash value
    for(size_t i = 0; i < 64; i++) {
        auto t1 = state[7] + sigma1(state[4]) + ch(state[4], state[5], state[6]) + K256[i] + data[i];
        auto t2 = sigma0(state[0]) + maj(state[0], state[1], state[2]);

        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = state[3] + t1;
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = t1 + t2;
    }

    return state;
}

}   // end of anonymous namespace (helper scope)


std::array<uint32_t, 8> hash(const std::string& inputString) {
    auto blocks = preprocess(inputString);
    auto digest = initial_hash;

    for(auto& block : blocks) {
        auto n = one_pass_hash(block, digest);
        for(size_t i = 0; i < 8; i++)
            digest[i] += n[i];
    }

    return digest;
}

}   // end of sha256 namespace

int main(int argc, char* argv[]) {
    std::string inputString((std::istreambuf_iterator<char>(std::cin)),
                            std::istreambuf_iterator<char>());

    for(auto i : sha256::hash(inputString))
        printf("%08x", i);
    printf("\n");

    return 0;
}
