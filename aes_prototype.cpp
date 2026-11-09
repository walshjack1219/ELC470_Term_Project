// ============================================================================
// ERASE WHEN DONE
//
//

//
// THE BIG PICTURE
// AES scrambles a 16-byte block using a 16-byte key. The 16 bytes are
// arranged in a 4x4 grid, filled column by column:
//
//        col0 col1 col2 col3
//   row0 [ 0    4    8   12 ]
//   row1 [ 1    5    9   13 ]      byte at (row r, col c) = state[r + 4*c]
//   row2 [ 2    6   10   14 ]
//   row3 [ 3    7   11   15 ]
//
// Encryption = 10 "rounds" of four simple steps. Decryption = the same steps
// undone in reverse order. Each TODO below is one of those steps.
//
// SPLITTING THE WORK
//   Jack: Part 1 (encrypt side)   xtime, subBytes, shiftRows, mixColumns, Part 3 (keyExpansion)
//   Padmaja B: Part 2 (decrypt side)   invSubBytes, invShiftRows, invMixColumns Part 4 (encrypt / decrypt loops)
// 
// main() checks each function on its own, so you can test your half
// without waiting.
// ============================================================================







// Run on windows with g++ -std=c++17 -Wall aes_prototype.cpp -o aes.exe; if ($?) { .\aes.exe }
// NOTE FOR US: delete the .exe file before committing changes to github



// libraries needed for the projects
#include <array>
#include <cstdint>
#include <cstdio>

//allows us to refer to a 16-byte block as "Block" instead of "std::array<uint8_t, 16>" which saves a ton of time
using Block = std::array<uint8_t, 16>;

// S-box from AN953 Table 3 (the inverse table is built from it in main).
// AI generated 
const uint8_t SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
uint8_t INV_SBOX[256];   // filled in by main()


//DONE

// ============================================================================
// PART 1 (JACK) - Encryption steps
// ============================================================================


// Alot of these functions are based on the AES pdf file provided on canvas. 


// xtime: multiply a byte by 2 in AES math (AN953 p.6).
// Shift left by 1. If the top bit (0x80) was set BEFORE shifting, XOR with 0x1b.
uint8_t xtime(uint8_t a) {
    
    if (a < 0x80) {
        a <<=1;

    } else {
        a = (a << 1) ^ 0x1b;
    }

    return a;
}

// addRoundKey: XOR each of the 16 state bytes with the matching key byte.
void addRoundKey(Block& state, const Block& roundKey) {

    //XORing each byte of the state with the corresponding byte of the roundKey

    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];     
    }

}

// subBytes: replace every byte with its S-box entry: state[i] = SBOX[state[i]]
void subBytes(Block& state) {
    
    for (int i = 0 ; i < 16; i++){
        state[i] = SBOX[state[i]];
    }
    
}

// shiftRows: rotate row r of the grid LEFT by r places (row 0 stays put).
void shiftRows(Block& state) {
    
    for (int r = 1; r < 4 ; r++){
        uint8_t temp[4];
        for (int c = 0; c < 4; c++){
            temp[c] = state[r + 4*c];
        }
        for (int c = 0; c < 4; c++){
            state[r + 4*c] = temp[(c + r) % 4];
        }
    }

}

// mixColumns: scramble each column (4 bytes a0..a3) into b0..b3.
// "2*x" means xtime(x), "3*x" means xtime(x) ^ x, and "+" means XOR:
//   b0 = 2*a0 + 3*a1 +   a2 +   a3
//   b1 =   a0 + 2*a1 + 3*a2 +   a3
//   b2 =   a0 +   a1 + 2*a2 + 3*a3
//   b3 = 3*a0 +   a1 +   a2 + 2*a3
// Column c is state[4*c] .. state[4*c + 3].
void mixColumns(Block& state) {
    
    //loops through each column
    for(int c = 0; c < 4; c++){
        //sets the temp vars to the values in the block
        uint8_t a0 = state[4*c];
        uint8_t a1 = state[4*c + 1];
        uint8_t a2 = state[4*c + 2];
        uint8_t a3 = state[4*c + 3];    

        //performs the mix columns op from the AES pdf
        uint8_t b0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        uint8_t b1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        uint8_t b2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        uint8_t b3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);

        //sets the new values 
        state[4*c] = b0;
        state[4*c+1] = b1;
        state[4*c+2] = b2;
        state[4*c+3] = b3;
    }
    
}
















// ============================================================================
// PART 2 (Padmaja) - Decryption steps (each one undoes a Part 1 step)
// ============================================================================

// invSubBytes: same as subBytes but use INV_SBOX.
void invSubBytes(Block& state) {
    // TODO
}

// invShiftRows: rotate row r RIGHT by r places.
void invShiftRows(Block& state) {
    // TODO
}



// invMixColumns: same shape as mixColumns with bigger numbers:
//   b0 = 14*a0 + 11*a1 + 13*a2 +  9*a3
//   b1 =  9*a0 + 14*a1 + 11*a2 + 13*a3
//   b2 = 13*a0 +  9*a1 + 14*a2 + 11*a3
//   b3 = 11*a0 + 13*a1 +  9*a2 + 14*a3
// Hint: write a helper mul(a, n) that builds n*a from doublings.
//   e.g. 9*a = 8*a + a = xtime(xtime(xtime(a))) ^ a
uint8_t mul(uint8_t a, uint8_t n) {
    // TODO (optional helper, but it makes invMixColumns much shorter)
    return a;
}

void invMixColumns(Block& state) {
    // TODO
}
















// ============================================================================
// PART 3 (JACK) - Key expansion: turn 1 key into 11 round keys (AN953 p.6)
// ============================================================================
// roundKeys[0] is the original key. Build each roundKeys[i] from roundKeys[i-1].
// Think of the key as 4 columns: col0 = bytes 0-3, col1 = 4-7, col2 = 8-11,
// col3 = 12-15.
//   1. Take the LAST column of the previous key, rotate it up one byte,
//      and run each byte through SBOX:
//        t = { SBOX[prev[13]], SBOX[prev[14]], SBOX[prev[15]], SBOX[prev[12]] }
//   2. t[0] ^= rcon        (rcon starts at 0x01, then rcon = xtime(rcon)
//                           each round: 01 02 04 08 10 20 40 80 1b 36)
//   3. new col0 = prev col0 ^ t
//      new col1 = prev col1 ^ new col0
//      new col2 = prev col2 ^ new col1
//      new col3 = prev col3 ^ new col2
// Check: round key 1 for key 2b7e1516... should be a0fafe17 88542cb1 23a33939 2a6c7605
void keyExpansion(const Block& key, Block roundKeys[11]) {
    roundKeys[0] = key;
    
    uint8_t rcon = 0x01;//put here before the loop since it was multiplying by 2 each round

    for (int i = 1; i <= 10; ++i) {
        Block& prev = roundKeys[i - 1];
        Block& curr = roundKeys[i];

        // Rotate and substitute
        uint8_t t[4] = { SBOX[prev[13]], SBOX[prev[14]], SBOX[prev[15]], SBOX[prev[12]] };

        
        t[0] ^= rcon;
        rcon = xtime(rcon);// once per round, right after using it

        // Generate new round key
        for (int j = 0; j < 4; ++j) {
            curr[j] = prev[j] ^ t[j];
            t[j] = curr[j]; // Update t for the next column
        }
        for (int j = 4; j < 16; ++j) {
            curr[j] = prev[j] ^ curr[j - 4];
        }
    }
    

}

















// ============================================================================
// PART 4 (Padmaja)- Putting it together
// ============================================================================

// encrypt:
//   addRoundKey with roundKeys[0]
//   rounds 1 to 9:  subBytes, shiftRows, mixColumns, addRoundKey(roundKeys[round])
//   round 10:       subBytes, shiftRows, addRoundKey(roundKeys[10])   (no mixColumns)
Block encrypt(Block state, const Block& key) {
    Block roundKeys[11];
    keyExpansion(key, roundKeys);
    // TODO
    return state;
}

// decrypt: the encrypt steps backwards, round keys used from 10 down to 0:
//   addRoundKey with roundKeys[10]
//   rounds 9 down to 1: invShiftRows, invSubBytes, addRoundKey(roundKeys[round]), invMixColumns
//   last:               invShiftRows, invSubBytes, addRoundKey(roundKeys[0])
Block decrypt(Block state, const Block& key) {
    Block roundKeys[11];
    keyExpansion(key, roundKeys);
    // TODO
    return state;
}












// ============================================================================
// Testing and demo (AI GENERATED FOR TESTING PURPOSES)
// ============================================================================
Block fromHex(const char* hex) {
    Block b{};
    for (int i = 0; i < 16; ++i) std::sscanf(hex + 2 * i, "%2hhx", &b[i]);
    return b;
}

void print(const char* label, const Block& b) {
    std::printf("%-14s", label);
    for (uint8_t x : b) std::printf("%02x", x);
    std::printf("\n");
}

void check(const char* name, const Block& got, const char* expectedHex) {
    bool ok = (got == fromHex(expectedHex));
    std::printf("  %-5s %s\n", ok ? "PASS" : "FAIL", name);
}

int main() {


    std::printf("xtime(80) = %02x\n", xtime(0x80));

    for (int i = 0; i < 256; ++i) INV_SBOX[SBOX[i]] = i;

    //temp check for part 3 

    Block test[11];
    keyExpansion(fromHex("2b7e151628aed2a6abf7158809cf4f3c"), test);
    for (int i = 0; i < 11; ++i) {
        std::printf("%2d  ", i);
        for (int b = 0; b < 16; ++b) {
            std::printf("%02x", test[i][b]);
            if (b % 4 == 3) std::printf(" ");
        }
        std::printf("\n");
    }




    // Individual checks. Inputs and outputs come from FIPS-197 Appendix B, round 1.
    std::printf("Function checks:\n");
    Block s;
    s = fromHex("3243f6a8885a308d313198a2e0370734");
    addRoundKey(s, fromHex("2b7e151628aed2a6abf7158809cf4f3c"));
    check("addRoundKey", s, "193de3bea0f4e22b9ac68d2ae9f84808");
    subBytes(s);      check("subBytes",      s, "d42711aee0bf98f1b8b45de51e415230");
    shiftRows(s);     check("shiftRows",     s, "d4bf5d30e0b452aeb84111f11e2798e5");
    mixColumns(s);    check("mixColumns",    s, "046681e5e0cb199a48f8d37a2806264c");
    invMixColumns(s); check("invMixColumns", s, "d4bf5d30e0b452aeb84111f11e2798e5");
    invShiftRows(s);  check("invShiftRows",  s, "d42711aee0bf98f1b8b45de51e415230");
    invSubBytes(s);   check("invSubBytes",   s, "193de3bea0f4e22b9ac68d2ae9f84808");
    Block rk[11];
    keyExpansion(fromHex("2b7e151628aed2a6abf7158809cf4f3c"), rk);
    check("keyExpansion",  rk[10], "d014f9a8c9ee2589e13f0cc8b6630ca6");

    // Full demo, FIPS-197 Appendix C.1
    std::printf("\nDemo (FIPS-197 Appendix C.1):\n");
    Block key = fromHex("000102030405060708090a0b0c0d0e0f");
    Block pt  = fromHex("00112233445566778899aabbccddeeff");
    Block ct  = encrypt(pt, key);
    Block back = decrypt(ct, key);
    print("  key", key);
    print("  plaintext", pt);
    print("  ciphertext", ct);
    print("  decrypted", back);
    check("encrypt", ct,   "69c4e0d86a7b0430d8cdb78070b4c55a");
    check("decrypt", back, "00112233445566778899aabbccddeeff");
    return 0;
}
