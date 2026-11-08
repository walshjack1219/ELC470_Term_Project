// ============================================================================
// aes.h  -  ELC 470 AES-128 software prototype
//
// Everything in one place: the data types, the byte layout, and the list of
// functions you will write. Read this file first, then open aes.cpp.
// ============================================================================
#pragma once
#include <array>
#include <cstdint>
#include <string>
 
// ----------------------------------------------------------------------------
// Data types
// ----------------------------------------------------------------------------
// A Byte is 8 bits. A Block is 16 bytes = 128 bits.
// Plaintext, ciphertext and the key are all Blocks.
using Byte  = uint8_t;
using Block = std::array<Byte, 16>;
 
constexpr int NUM_ROUNDS = 10;   // AES-128 always does 10 rounds
 
// ----------------------------------------------------------------------------
// Byte layout  (FIPS-197 Section 3.4, AN953 Tables 1 and 2)
// ----------------------------------------------------------------------------
// AES thinks of a Block as a 4x4 grid called the "state".
// The 16 bytes fill the grid one COLUMN at a time:
//
//            col0  col1  col2  col3
//    row0  [   0     4     8    12 ]
//    row1  [   1     5     9    13 ]
//    row2  [   2     6    10    14 ]
//    row3  [   3     7    11    15 ]
//
// So the byte at (row r, column c) is   block[r + 4*c]
// The key uses the exact same layout.
 
// ----------------------------------------------------------------------------
// STEP 1 - Galois field math (the "multiply" AES uses)
// ----------------------------------------------------------------------------
Byte xtime(Byte a);              // a times 2 in GF(2^8)
Byte gmul(Byte a, Byte b);       // a times b in GF(2^8)
 
// ----------------------------------------------------------------------------
// STEP 2 to STEP 5 - The four round operations (each changes the state in place)
// ----------------------------------------------------------------------------
void addRoundKey(Block& state, const Block& roundKey);   // STEP 2
void subBytes(Block& state);                              // STEP 3
void invSubBytes(Block& state);
void shiftRows(Block& state);                             // STEP 4
void invShiftRows(Block& state);
void mixColumns(Block& state);                            // STEP 5
void invMixColumns(Block& state);
 
// ----------------------------------------------------------------------------
// STEP 6 - Key schedule, done "on the fly" like AN953
// ----------------------------------------------------------------------------
// Instead of storing all 11 round keys, we keep ONE 16-byte key and update it
// each round. This is also what the hardware will do (one 128-bit register).
void nextRoundKey(Block& key, Byte rcon);   // round key i   -> round key i+1
void prevRoundKey(Block& key, Byte rcon);   // round key i+1 -> round key i
Byte nextRcon(Byte rcon);                   // 01, 02, 04, ... 80, 1b, 36
Byte prevRcon(Byte rcon);                   // 36, 1b, 80, ... 02, 01
 
// ----------------------------------------------------------------------------
// Already written for you (in aes.cpp, bottom section)
// ----------------------------------------------------------------------------
Block calcDecodeKey(Block key);                    // run the key schedule 10 times
Block encrypt(Block plaintext, Block key);
Block decrypt(Block ciphertext, const Block& key); // takes the NORMAL key
 
// Top level that matches the block diagram in the project handout.
// MODE: 0b00 = encode, 0b01 = decode, 0b1X = encode and decode
struct AesOutputs {
    Block ciphertext{};
    Block plaintext{};
    bool  busy = false;
};
AesOutputs aesTop(unsigned mode, const Block& key,
                  const Block& plaintextIn, const Block& ciphertextIn);
 
// Helpers
Block       hexToBlock(const std::string& hex);   // "00112233..." -> Block
std::string blockToHex(const Block& b);            // Block -> "00112233..."
extern bool g_trace;                               // true = print every step
void trace(const std::string& label, int round, const Block& b);