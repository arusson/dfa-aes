#ifndef AES_H_
#define AES_H_

#define AES_ROUNDS_128 10

#define XTIME(b) ((b)<<1) ^ (((b)>>7)*0x1b)
#define TAKEBYTE(w,n) (byte)(((w)>>(24-8*n)) & 255)

typedef uint8_t byte;
typedef uint32_t word32;

extern const byte sbox[256];
extern const byte invsbox[256];
extern const byte rcon[10];

word32 bytes_to_word(const byte a[4]);
void word_to_bytes(const word32 a, byte b[4]);
void subBytes(byte state[16]);
void invSubBytes(byte state[16]);
void shiftRows(byte state[16]);
void invShiftRows(byte state[16]);
void mixColumn(byte col[4]);
void mixColumns(byte state[16]);
void invMixColumn(byte col[4]);
void invMixColumns(byte state[16]);
void keyExpansion(const byte masterkey[16], byte subkeys[176]);
void encrypt_aes(const byte input[16], byte output[16],
                 const byte subkeys[176], const int NR);

#endif /* AES_H_ */
