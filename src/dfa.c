#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "dfa.h"

#ifdef _OPENMP
#include "omp.h"
#endif

const int POSITIONS[4][4] = {
  {0, 13, 10, 7},
  {4, 1, 14, 11},
  {8, 5, 2, 15},
  {12, 9, 6, 3}
};

/*
 * row: fault position in column (-1 if unknown)
 * fault_list: values in [1, 255]
 */
int get_diff_MC(const int row, const int fault_list[255], const int fault_len,
                word32 list_diff[DIFF_MC_MAX]) {
  int i, pos;
  int list_diff_len = 0;
  int row_start = 0;
  int row_end = 4;
  byte col[4] = {0, 0, 0, 0};
  
  assert((row >= -1) && (row < 4));
  
  if (row != -1) {
    row_start = row;
    row_end = row + 1;
  }
  
  for (pos = row_start; pos < row_end; pos++) {
    for (i = 0; i < fault_len; i++) {
      memset(col, 0, 4);
      col[pos] = (byte)fault_list[i];
      mixColumn(col);
      list_diff[list_diff_len++] = bytes_to_word(col);
      
    }
  }
  return list_diff_len;
}

int k10_cand_from_diffMC(const byte ct[16], const byte fct[16], const int col,
                         const word32 diffMC_list[DIFF_MC_MAX],
                         const int diffMC_len, word32 candidates[CAND_MAX]) {
  int i, k0, k1, k2, k3;
  int cand_len = 0;
  byte diff, good[4], faulty[4];
  
  /* copy the 4 bytes of ct and fct that differ */
  for (i = 0; i < 4; i++) {
    good[i] = ct[POSITIONS[col][i]];
    faulty[i] = fct[POSITIONS[col][i]];
  }
  
  /* construct list of quadruplets candidates: */
  /* for each MC difference possible, find which (k0, k1, k2, k3) corresponds */
  for (i = 0; i < diffMC_len; i++) {
    for (k0 = 0; k0 < 256; k0++) {
      diff = invsbox[good[0] ^ (byte)k0] ^ invsbox[faulty[0] ^ (byte)k0];
      if (diff != TAKEBYTE(diffMC_list[i], 0)) {
        continue;
      }
      for (k1 = 0; k1 < 256; k1++) {
        diff = invsbox[good[1] ^ (byte)k1] ^ invsbox[faulty[1] ^ (byte)k1];
        if (diff != TAKEBYTE(diffMC_list[i], 1)) {
          continue;
        }
        for (k2 = 0; k2 < 256; k2++) {
          diff = invsbox[good[2] ^ (byte)k2] ^ invsbox[faulty[2] ^ (byte)k2];
          if (diff != TAKEBYTE(diffMC_list[i], 2)) {
            continue;
          }
          for (k3 = 0; k3 < 256; k3++) {
            diff = invsbox[good[3] ^ (byte)k3] ^ invsbox[faulty[3] ^ (byte)k3];
            if (diff != TAKEBYTE(diffMC_list[i], 3)) {
              continue;
            }
            candidates[cand_len++] = ((word32)k0 << 24) |
              ((word32)k1 << 16) | ((word32)k2 << 8) | (word32)k3;
          } /* end for k3 */
        } /* end for k2 */
      } /* end for k1 */
    } /* end for k0 */
  } /* end for i */
  
  return cand_len;
}

void intersection(word32 *list1, int *len1,
                  const word32 *list2, const int len2) {
  int i, j;
  int new_len = 0;
  for (i = 0; i < *len1; i++) {
    for (j = 0; j < len2; j++) {
      if (list1[i] == list2[j]) {
        list1[new_len++] = list2[j];
        break;
      }
    }
  }
  *len1 = new_len;
}

void reverseKeyExpansion(const byte subkey10[16], byte subkeys[176]) {
  int i;
  
  for (i = 160; i < 176; i++) {
    subkeys[i] = subkey10[i - 160];
  }
  
  for (i = 156; i >= 0; i -= 4) {
    if (i % 16 == 0) {
      subkeys[i] = subkeys[i + 16] ^ sbox[subkeys[i + 13]] ^ rcon[i >> 4];
      subkeys[i + 1] = subkeys[i + 17] ^ sbox[subkeys[i + 14]];
      subkeys[i + 2] = subkeys[i + 18] ^ sbox[subkeys[i + 15]];
      subkeys[i + 3] = subkeys[i + 19] ^ sbox[subkeys[i + 12]];
    }
    else {
      subkeys[i] = subkeys[i + 16] ^ subkeys[i + 12];
      subkeys[i + 1] = subkeys[i + 17] ^ subkeys[i + 13];
      subkeys[i + 2] = subkeys[i + 18] ^ subkeys[i + 14];
      subkeys[i + 3] = subkeys[i + 19] ^ subkeys[i + 15];
    }
  }
}

void k9_from_k10(const byte subkey10[16], byte subkey9[16]) {
  int i;

  for (i = 12; i > 0; i -= 4) {
    subkey9[i] = subkey10[i] ^ subkey10[i - 4];
    subkey9[i + 1] = subkey10[i + 1] ^ subkey10[i - 3];
    subkey9[i + 2] = subkey10[i + 2] ^ subkey10[i - 2];
    subkey9[i + 3] = subkey10[i + 3] ^ subkey10[i - 1];
  }
  subkey9[0] = subkey10[0] ^ sbox[subkey9[13]] ^ rcon[9];
  subkey9[1] = subkey10[1] ^ sbox[subkey9[14]];
  subkey9[2] = subkey10[2] ^ sbox[subkey9[15]];
  subkey9[3] = subkey10[3] ^ sbox[subkey9[12]];
}

int exhaustive_search(const byte pt[16], const byte ct[16],
                      const word32 candidates[4][CAND_MAX],
                      const int cand_len[4], byte masterkey[16]) {
  int i, j, k, l;
  byte subkey10[16];
  byte subkeys[176];
  byte ctcmp[16];
  int found = 0;
  
#ifdef _OPENMP
#pragma omp parallel for private(subkey10,subkeys,ctcmp,j,k,l) shared(found)
#endif
  for (i = 0; i < cand_len[0]; i++) {
    if (found) { continue; }    
    fprintf(stderr, "Progress: %d/%d\n", i + 1, cand_len[0]);
    subkey10[0]  = TAKEBYTE(candidates[0][i], 0);
    subkey10[13] = TAKEBYTE(candidates[0][i], 1);
    subkey10[10] = TAKEBYTE(candidates[0][i], 2);
    subkey10[7]  = TAKEBYTE(candidates[0][i], 3);
    
    for (j = 0; j < cand_len[1]; j++) {
      subkey10[4]  = TAKEBYTE(candidates[1][j], 0);
      subkey10[1]  = TAKEBYTE(candidates[1][j], 1);
      subkey10[14] = TAKEBYTE(candidates[1][j], 2);
      subkey10[11] = TAKEBYTE(candidates[1][j], 3);
      
      for (k = 0; k < cand_len[2]; k++) {
        subkey10[8]  = TAKEBYTE(candidates[2][k], 0);
        subkey10[5]  = TAKEBYTE(candidates[2][k], 1);
        subkey10[2]  = TAKEBYTE(candidates[2][k], 2);
        subkey10[15] = TAKEBYTE(candidates[2][k], 3);
        
        for (l = 0; l < cand_len[3]; l++) {
          subkey10[12] = TAKEBYTE(candidates[3][l], 0);
          subkey10[9]  = TAKEBYTE(candidates[3][l], 1);
          subkey10[6]  = TAKEBYTE(candidates[3][l], 2);
          subkey10[3]  = TAKEBYTE(candidates[3][l], 3);

          reverseKeyExpansion(subkey10, subkeys);
          encrypt_aes(pt, ctcmp, subkeys, AES_ROUNDS_128);
          if (memcmp(ct, ctcmp, 16) == 0) {
            memcpy(masterkey, subkeys, 16);
            found = 1;
          }
        } /* end for l */
      } /* end for k */
    } /* end for j */
  } /* end for i */
  return found;
}
