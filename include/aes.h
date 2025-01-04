#ifndef AES_H_
#define AES_H_

#define XTIME(b) ((b)<<1) ^ (((b)>>7)*0x1b)

extern const uint8_t sbox[256];
extern const uint8_t invsbox[256];
extern const uint8_t rcon[10];

void mix_column(uint8_t col[4]);
void encrypt_aes(const uint8_t input[16], uint8_t output[16], const uint8_t subkeys[176]);

#endif /* AES_H_ */
