#ifndef AES_H_
#define AES_H_

#define XTIME(b) ((b)<<1) ^ (((b)>>7)*0x1b)

extern const uint8_t sbox[256];
extern const uint8_t invsbox[256];
extern const uint8_t rcon[10];

void mix_column(uint8_t col[4]);
void inv_mix_column(uint8_t a[4]);
void key_expansion(const uint8_t masterkey[16], uint8_t subkeys[176]);
void k1_from_masterkey(const uint8_t masterkey[16], uint8_t subkey2[16]);
void reverse_key_expansion(const uint8_t subkey10[16], uint8_t subkeys[176]);
void k9_from_k10(const uint8_t subkey10[16], uint8_t subkey9[16]);
void encrypt_aes(const uint8_t input[16], uint8_t output[16], const uint8_t subkeys[176]);

#endif /* AES_H_ */
