// ============================================================================
// main.cpp  -  Tests, demo, and command line (nothing to change here)
//
//   ./aes                              step-by-step tests (use while building)
//   ./aes demo                         run all MODEs on the FIPS-197 examples
//   ./aes trace                        same, printing every step of every round
//   ./aes <mode> <key> <pt> <ct>       one run, like the hardware ports
//        mode = 00, 01, 10 or 11       key/pt/ct = 32 hex characters (or 0)
//        example: ./aes 00 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff 0
//
// Every expected value below comes from FIPS-197 (Section 4.2 for the math,
// Appendix A.1 for the key schedule, Appendices B and C.1 for the cipher).
// ============================================================================
#include "aes.h"
#include "aes_tables.h"
 
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
 
// ---------------------------------------------------------------------------- tiny test helper
struct StepResult {
    bool ok = true;
    std::string why;   // first failure only, to keep output short
};
 
static std::string hex2(Byte b) {
    char buf[3];
    std::snprintf(buf, sizeof buf, "%02x", b);
    return buf;
}
 
static void expectByte(StepResult& r, const std::string& what, Byte got, Byte want) {
    if (r.ok && got != want) {
        r.ok  = false;
        r.why = what + ": expected " + hex2(want) + ", got " + hex2(got);
    }
}
 
static void expectBlock(StepResult& r, const std::string& what,
                        const Block& got, const std::string& wantHex) {
    std::string g = blockToHex(got);
    if (r.ok && g != wantHex) {
        r.ok  = false;
        r.why = what + "\n        expected " + wantHex + "\n        got      " + g;
    }
}
 
static bool report(const std::string& name, const StepResult& r) {
    std::cout << (r.ok ? "  PASS  " : "  FAIL  ") << name << "\n";
    if (!r.ok) std::cout << "        " << r.why << "\n";
    return r.ok;
}
 
// ---------------------------------------------------------------------------- the step tests
static int runStepTests() {
    std::cout << "AES-128 step tests\n\n";
    int fails = 0;
 
    {   // STEP 0: tables (should always pass)
        StepResult r;
        expectByte(r, "SBOX[0x53]", SBOX[0x53], 0xed);
        for (int x = 0; x < 256 && r.ok; ++x)
            expectByte(r, "INV_SBOX[SBOX[" + hex2(Byte(x)) + "]]",
                       INV_SBOX[SBOX[x]], Byte(x));
        fails += !report("Step 0  lookup tables", r);
    }
    {   // STEP 1: GF math, FIPS-197 Section 4.2
        StepResult r;
        expectByte(r, "xtime(57)", xtime(0x57), 0xae);
        expectByte(r, "xtime(ae)", xtime(0xae), 0x47);   // top bit set -> ^1b
        expectByte(r, "xtime(80)", xtime(0x80), 0x1b);
        expectByte(r, "gmul(57,13)", gmul(0x57, 0x13), 0xfe);
        expectByte(r, "gmul(57,83)", gmul(0x57, 0x83), 0xc1);
        fails += !report("Step 1  xtime / gmul", r);
    }
    {   // STEP 2: AddRoundKey, FIPS-197 Appendix B (input ^ key = round 1 start)
        StepResult r;
        Block s = hexToBlock("3243f6a8885a308d313198a2e0370734");
        addRoundKey(s, hexToBlock("2b7e151628aed2a6abf7158809cf4f3c"));
        expectBlock(r, "addRoundKey", s, "193de3bea0f4e22b9ac68d2ae9f84808");
        fails += !report("Step 2  addRoundKey", r);
    }
    {   // STEP 3: SubBytes, FIPS-197 Appendix B round 1
        StepResult r;
        Block s = hexToBlock("193de3bea0f4e22b9ac68d2ae9f84808");
        subBytes(s);
        expectBlock(r, "subBytes", s, "d42711aee0bf98f1b8b45de51e415230");
        invSubBytes(s);
        expectBlock(r, "invSubBytes (should undo subBytes)", s,
                    "193de3bea0f4e22b9ac68d2ae9f84808");
        fails += !report("Step 3  subBytes / invSubBytes", r);
    }
    {   // STEP 4: ShiftRows
        StepResult r;
        Block s = hexToBlock("000102030405060708090a0b0c0d0e0f");
        shiftRows(s);
        expectBlock(r, "shiftRows on 00..0f", s, "00050a0f04090e03080d02070c01060b");
        s = hexToBlock("d42711aee0bf98f1b8b45de51e415230");   // App. B round 1
        shiftRows(s);
        expectBlock(r, "shiftRows (App. B)", s, "d4bf5d30e0b452aeb84111f11e2798e5");
        invShiftRows(s);
        expectBlock(r, "invShiftRows (should undo shiftRows)", s,
                    "d42711aee0bf98f1b8b45de51e415230");
        fails += !report("Step 4  shiftRows / invShiftRows", r);
    }
    {   // STEP 5: MixColumns, FIPS-197 Appendix B round 1
        StepResult r;
        Block s = hexToBlock("d4bf5d30e0b452aeb84111f11e2798e5");
        mixColumns(s);
        expectBlock(r, "mixColumns", s, "046681e5e0cb199a48f8d37a2806264c");
        invMixColumns(s);
        expectBlock(r, "invMixColumns (should undo mixColumns)", s,
                    "d4bf5d30e0b452aeb84111f11e2798e5");
        fails += !report("Step 5  mixColumns / invMixColumns", r);
    }
    {   // STEP 6: key schedule, FIPS-197 Appendix A.1
        StepResult r;
        Block k = hexToBlock("2b7e151628aed2a6abf7158809cf4f3c");
        nextRoundKey(k, 0x01);
        expectBlock(r, "nextRoundKey (round 1)", k, "a0fafe1788542cb123a339392a6c7605");
        prevRoundKey(k, 0x01);
        expectBlock(r, "prevRoundKey (back to round 0)", k,
                    "2b7e151628aed2a6abf7158809cf4f3c");
        expectByte(r, "prevRcon(36)", prevRcon(0x36), 0x1b);
        expectByte(r, "prevRcon(1b)", prevRcon(0x1b), 0x80);
        expectByte(r, "prevRcon(02)", prevRcon(0x02), 0x01);
        expectBlock(r, "calcDecodeKey (round 10)", calcDecodeKey(
                    hexToBlock("2b7e151628aed2a6abf7158809cf4f3c")),
                    "d014f9a8c9ee2589e13f0cc8b6630ca6");
        fails += !report("Step 6  key schedule", r);
    }
    {   // STEP 7: whole cipher, FIPS-197 Appendices B and C.1
        StepResult r;
        Block k1 = hexToBlock("2b7e151628aed2a6abf7158809cf4f3c");
        Block k2 = hexToBlock("000102030405060708090a0b0c0d0e0f");
        expectBlock(r, "encrypt (App. B)",
                    encrypt(hexToBlock("3243f6a8885a308d313198a2e0370734"), k1),
                    "3925841d02dc09fbdc118597196a0b32");
        expectBlock(r, "encrypt (App. C.1)",
                    encrypt(hexToBlock("00112233445566778899aabbccddeeff"), k2),
                    "69c4e0d86a7b0430d8cdb78070b4c55a");
        expectBlock(r, "decrypt (App. B)",
                    decrypt(hexToBlock("3925841d02dc09fbdc118597196a0b32"), k1),
                    "3243f6a8885a308d313198a2e0370734");
        expectBlock(r, "decrypt (App. C.1)",
                    decrypt(hexToBlock("69c4e0d86a7b0430d8cdb78070b4c55a"), k2),
                    "00112233445566778899aabbccddeeff");
        fails += !report("Step 7  full encrypt / decrypt", r);
    }
 
    std::cout << "\n" << (fails == 0
        ? "All steps pass. Try ./aes demo next.\n"
        : "Fix the first FAIL above, rebuild, and run again.\n");
    return fails == 0 ? 0 : 1;
}
 
// ---------------------------------------------------------------------------- demo
struct Example { const char* name; const char* key; const char* pt; const char* ct; };
 
static const std::vector<Example> EXAMPLES = {
    {"FIPS-197 Appendix B",   "2b7e151628aed2a6abf7158809cf4f3c",
                              "3243f6a8885a308d313198a2e0370734",
                              "3925841d02dc09fbdc118597196a0b32"},
    {"FIPS-197 Appendix C.1", "000102030405060708090a0b0c0d0e0f",
                              "00112233445566778899aabbccddeeff",
                              "69c4e0d86a7b0430d8cdb78070b4c55a"},
};
 
// Runs every MODE on each example and writes vectors.hex for the
// SystemVerilog testbench. Each line = KEY PT CT (384 bits) for $readmemh.
static int runDemo() {
    int fails = 0;
    std::ofstream vectors("vectors.hex");
    for (const auto& ex : EXAMPLES) {
        Block key = hexToBlock(ex.key), pt = hexToBlock(ex.pt), ct = hexToBlock(ex.ct);
        std::cout << "==== " << ex.name << " ====\n"
                  << "KEY        " << ex.key << "\n"
                  << "PLAINTEXT  " << ex.pt  << "\n"
                  << "CYPHERTEXT " << ex.ct  << "\n\n";
 
        std::cout << "MODE 00 (encode)\n";
        AesOutputs e = aesTop(0b00, key, pt, Block{});
        bool okE = e.ciphertext == ct;
        std::cout << "  CYPHERTEXT out " << blockToHex(e.ciphertext) << (okE ? "  PASS\n\n" : "  FAIL\n\n");
 
        std::cout << "MODE 01 (decode)\n";
        AesOutputs d = aesTop(0b01, key, Block{}, ct);
        bool okD = d.plaintext == pt;
        std::cout << "  PLAINTEXT out  " << blockToHex(d.plaintext) << (okD ? "  PASS\n\n" : "  FAIL\n\n");
 
        std::cout << "MODE 1X (encode and decode)\n";
        AesOutputs b = aesTop(0b10, key, pt, ct);
        bool okB = b.ciphertext == ct && b.plaintext == pt;
        std::cout << "  CYPHERTEXT out " << blockToHex(b.ciphertext) << "\n"
                  << "  PLAINTEXT out  " << blockToHex(b.plaintext)  << (okB ? "  PASS\n\n" : "  FAIL\n\n");
 
        fails += !okE + !okD + !okB;
        vectors << ex.key << ex.pt << ex.ct << "\n";
    }
    std::cout << (fails ? "SOME CHECKS FAILED\n" : "ALL CHECKS PASSED\n")
              << "(test vectors written to vectors.hex)\n";
    return fails ? 1 : 0;
}
 
// ---------------------------------------------------------------------------- main
int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
 
        if (args.empty())         return runStepTests();
        if (args[0] == "demo")    return runDemo();
        if (args[0] == "trace") { g_trace = true; return runDemo(); }
 
        if (args.size() == 4) {
            unsigned mode = std::stoul(args[0], nullptr, 2);
            auto blk = [](const std::string& s) { return s == "0" ? Block{} : hexToBlock(s); };
            AesOutputs o = aesTop(mode, blk(args[1]), blk(args[2]), blk(args[3]));
            if (mode == 0b00 || (mode & 0b10)) std::cout << "CYPHERTEXT " << blockToHex(o.ciphertext) << "\n";
            if (mode == 0b01 || (mode & 0b10)) std::cout << "PLAINTEXT  " << blockToHex(o.plaintext)  << "\n";
            return 0;
        }
 
        std::cerr << "usage: ./aes | ./aes demo | ./aes trace | ./aes <mode> <key> <pt> <ct>\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}