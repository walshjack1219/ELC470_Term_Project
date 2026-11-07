// ============================================================================
// ELC 470 - AES-128 Software Prototype (skeleton)
// Mirrors the hardware block diagram: MODE, KEY, PLAINTEXT, CYPHERTEXT in;
// CYPHERTEXT, PLAINTEXT, BUSY out.
//
// Build:  g++ -std=c++17 -Wall -O2 aes128.cpp -o aes
// Run:    ./aes                         -> runs FIPS-197 self-tests
//         ./aes -v                      -> self-tests with round-by-round trace
//         ./aes <mode> <key> <pt> <ct>  -> one operation (hex, 32 chars each)
//            e.g. ./aes 00 000102...0f 001122...ff 0
// ============================================================================
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Byte      = uint8_t;
using Block     = std::array<Byte, 16>;                 // 128-bit block or key
using State     = std::array<std::array<Byte, 4>, 4>;   // state[row][col]
using RoundKeys = std::array<Block, 11>;                // round keys 0..10

constexpr int NR = 10;   // AES-128 rounds
bool g_trace = false;    // print state after every step when true

// ----------------------------------------------------------------------------
// Lookup tables
// ----------------------------------------------------------------------------
// TODO: fill in from FIPS-197 Figure 7 (S-box) and Figure 14 (inverse S-box),
//       or write buildSBoxes() to compute them (GF(2^8) inverse + affine map).
Byte SBOX[256]     = { /* TODO */ };
Byte INV_SBOX[256] = { /* TODO */ };

// Round constants for key expansion (first byte of Rcon[i]); index 0 unused.
const Byte RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                       0x20, 0x40, 0x80, 0x1b, 0x36};

// ----------------------------------------------------------------------------
// Utilities (done)
// ----------------------------------------------------------------------------
Block hexToBlock(const std::string& hex) {
    if (hex.size() != 32) throw std::invalid_argument("need 32 hex chars: " + hex);
    Block b{};
    for (int i = 0; i < 16; ++i)
        b[i] = static_cast<Byte>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return b;
}

std::string blockToHex(const Block& b) {
    std::ostringstream os;
    for (Byte x : b) os << std::hex << std::setw(2) << std::setfill('0') << int(x);
    return os.str();
}

// FIPS-197 column-major mapping: in[r + 4c] -> state[r][c]
State toState(const Block& in) {
    State s{};
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r) s[r][c] = in[r + 4 * c];
    return s;
}

Block fromState(const State& s) {
    Block out{};
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r) out[r + 4 * c] = s[r][c];
    return out;
}

void trace(const std::string& label, int round, const State& s) {
    if (!g_trace) return;
    std::cout << "  round[" << std::setw(2) << std::dec << round << "]."
              << std::left << std::setw(10) << label << std::right
              << blockToHex(fromState(s)) << "\n";
}

// ----------------------------------------------------------------------------
// GF(2^8) arithmetic
// ----------------------------------------------------------------------------
// Multiply by x (i.e. 0x02) modulo x^8 + x^4 + x^3 + x + 1 (0x11b)
Byte xtime(Byte a) {
    // TODO: shift left; if the high bit was set, XOR with 0x1b
    (void)a;
    return 0;
}

// General multiply (needed for InvMixColumns: 0x09, 0x0b, 0x0d, 0x0e)
Byte gmul(Byte a, Byte b) {
    // TODO: shift-and-add using xtime()
    (void)a; (void)b;
    return 0;
}

// ----------------------------------------------------------------------------
// Key expansion  (FIPS-197 Section 5.2)
// ----------------------------------------------------------------------------
RoundKeys keyExpansion(const Block& key) {
    RoundKeys rk{};
    // TODO:
    //  - words w[0..43], each 4 bytes; w[0..3] = key
    //  - for i >= 4: temp = w[i-1];
    //        if i % 4 == 0: temp = SubWord(RotWord(temp)) ^ Rcon[i/4]
    //        w[i] = w[i-4] ^ temp
    //  - pack w[4r .. 4r+3] into rk[r]
    //  Check against FIPS-197 Appendix A.1
    (void)key;
    return rk;
}

// ----------------------------------------------------------------------------
// Round transformations  (FIPS-197 Section 5.1 and 5.3)
// ----------------------------------------------------------------------------
void addRoundKey(State& s, const Block& rk) {
    // TODO: s[r][c] ^= rk[r + 4c]
    (void)s; (void)rk;
}

void subBytes(State& s)       { /* TODO: s[r][c] = SBOX[s[r][c]] */ (void)s; }
void invSubBytes(State& s)    { /* TODO: use INV_SBOX */ (void)s; }

void shiftRows(State& s)      { /* TODO: rotate row r LEFT by r */ (void)s; }
void invShiftRows(State& s)   { /* TODO: rotate row r RIGHT by r */ (void)s; }

void mixColumns(State& s) {
    // TODO: each column times matrix [02 03 01 01; 01 02 03 01; 01 01 02 03; 03 01 01 02]
    (void)s;
}

void invMixColumns(State& s) {
    // TODO: each column times matrix [0e 0b 0d 09; 09 0e 0b 0d; 0d 09 0e 0b; 0b 0d 09 0e]
    (void)s;
}

// ----------------------------------------------------------------------------
// Cipher / Inverse Cipher  (round structure done; fill in the steps above)
// ----------------------------------------------------------------------------
Block encrypt(const Block& pt, const RoundKeys& rk) {
    State s = toState(pt);
    trace("input", 0, s);
    addRoundKey(s, rk[0]);
    for (int r = 1; r < NR; ++r) {
        trace("start", r, s);
        subBytes(s);    trace("s_box", r, s);
        shiftRows(s);   trace("s_row", r, s);
        mixColumns(s);  trace("m_col", r, s);
        addRoundKey(s, rk[r]);
    }
    trace("start", NR, s);
    subBytes(s);   trace("s_box", NR, s);
    shiftRows(s);  trace("s_row", NR, s);
    addRoundKey(s, rk[NR]);
    trace("output", NR, s);
    return fromState(s);
}

Block decrypt(const Block& ct, const RoundKeys& rk) {
    State s = toState(ct);
    trace("iinput", 0, s);
    addRoundKey(s, rk[NR]);
    for (int r = NR - 1; r > 0; --r) {
        trace("istart", NR - r, s);
        invShiftRows(s);  trace("is_row", NR - r, s);
        invSubBytes(s);   trace("is_box", NR - r, s);
        addRoundKey(s, rk[r]);
        invMixColumns(s);
    }
    trace("istart", NR, s);
    invShiftRows(s);  trace("is_row", NR, s);
    invSubBytes(s);   trace("is_box", NR, s);
    addRoundKey(s, rk[0]);
    trace("ioutput", NR, s);
    return fromState(s);
}

// ----------------------------------------------------------------------------
// Top level - mirrors the hardware ports
// MODE: 00 = encode, 01 = decode, 1X = encode and decode
// ----------------------------------------------------------------------------
struct AesOutputs {
    Block ciphertext{};
    Block plaintext{};
    bool  busy = false;
};

AesOutputs aesTop(unsigned mode, const Block& key,
                  const Block& ptIn, const Block& ctIn) {
    AesOutputs out;
    out.busy = true;                     // hardware would hold BUSY high here
    RoundKeys rk = keyExpansion(key);
    if (mode == 0b00 || (mode & 0b10)) out.ciphertext = encrypt(ptIn, rk);
    if (mode == 0b01 || (mode & 0b10)) out.plaintext  = decrypt(ctIn, rk);
    out.busy = false;
    return out;
}

// ----------------------------------------------------------------------------
// Self-test with FIPS-197 vectors + vector file for the SystemVerilog testbench
// ----------------------------------------------------------------------------
struct Vector { const char* name; const char* key; const char* pt; const char* ct; };

const std::vector<Vector> VECTORS = {
    {"FIPS-197 App. B",   "2b7e151628aed2a6abf7158809cf4f3c",
                          "3243f6a8885a308d313198a2e0370734",
                          "3925841d02dc09fbdc118597196a0b32"},
    {"FIPS-197 App. C.1", "000102030405060708090a0b0c0d0e0f",
                          "00112233445566778899aabbccddeeff",
                          "69c4e0d86a7b0430d8cdb78070b4c55a"},
};

int runSelfTests() {
    int fails = 0;
    std::ofstream vec("vectors.hex");    // one line per vector: KEY PT CT
    for (const auto& v : VECTORS) {
        Block key = hexToBlock(v.key), pt = hexToBlock(v.pt), ct = hexToBlock(v.ct);
        std::cout << "== " << v.name << " ==\n";
        AesOutputs o = aesTop(0b10, key, pt, ct);   // encode and decode
        bool encOk = o.ciphertext == ct;
        bool decOk = o.plaintext  == pt;
        // round trip: decrypt what we just encrypted
        bool rtOk  = aesTop(0b01, key, pt, o.ciphertext).plaintext == pt;

        std::cout << "  key      " << v.key << "\n"
                  << "  pt in    " << v.pt  << "\n"
                  << "  ct out   " << blockToHex(o.ciphertext) << (encOk ? "  PASS" : "  FAIL") << "\n"
                  << "  ct in    " << v.ct  << "\n"
                  << "  pt out   " << blockToHex(o.plaintext)  << (decOk ? "  PASS" : "  FAIL") << "\n"
                  << "  roundtrip" << (rtOk ? "  PASS" : "  FAIL") << "\n\n";
        fails += !encOk + !decOk + !rtOk;
        vec << v.key << v.pt << v.ct << "\n";       // 384-bit word for $readmemh
    }
    std::cout << (fails ? "SOME TESTS FAILED\n" : "ALL TESTS PASSED\n");
    return fails ? 1 : 0;
}

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        if (!args.empty() && args[0] == "-v") { g_trace = true; args.erase(args.begin()); }

        if (args.empty()) return runSelfTests();

        if (args.size() != 4) {
            std::cerr << "usage: aes [-v] <mode 00|01|10|11> <key> <pt> <ct>\n"
                         "       (use 0 for an unused pt/ct)\n";
            return 2;
        }
        unsigned mode = std::stoul(args[0], nullptr, 2);
        auto blk = [](const std::string& s) { return s == "0" ? Block{} : hexToBlock(s); };
        AesOutputs o = aesTop(mode, blk(args[1]), blk(args[2]), blk(args[3]));
        if (mode == 0b00 || (mode & 0b10)) std::cout << "CYPHERTEXT " << blockToHex(o.ciphertext) << "\n";
        if (mode == 0b01 || (mode & 0b10)) std::cout << "PLAINTEXT  " << blockToHex(o.plaintext)  << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}
