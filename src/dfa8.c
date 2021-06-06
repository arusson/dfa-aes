#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dfa.h"

#ifdef _OPENMP
#include "omp.h"
#endif

void r8_get_diffMC(const int col8, const word32 diff_col, const int col9,
                   word32 diffMC_list[DIFF_MC_MAX], int *len) {
  int i, c1, c2, diff;
  int fault_list[255];
  int fault_list_len = 0;
  int row9 = -1;
  
  /* if fault position is known */
  if (col8 != -1) {
    row9 = (col8 + 3*col9) % 4;
  }
  
  /* case 1: fault in round 8 is known */
  if (diff_col != 0) {
    diff = (int)TAKEBYTE(diff_col, row9);
    for (c1 = 1; c1 < 255; c1++) {
      c2 = diff ^ c1;
      if (c1 > c2) { continue; }
      /* fault_list_len = 127 */
      fault_list[fault_list_len++] = (int)(sbox[c1] ^ sbox[c2]); 
    }
  }
  /* case 2: unknown fault */
  else {
    for (i = 0; i < 255; i++) {
      fault_list[i] = i + 1;
    }
    fault_list_len = 255;
  }
  
  /* construct the MC differences table */
  *len = get_diff_MC(row9, fault_list, fault_list_len, diffMC_list);
}

void r8_find_candidates(const byte ct[16], const byte fct[16],
                        const int row8, const int col8, const int fault,
                        word32 candidates[4][CAND_MAX], int cand_len[4]) {
  byte tmp[4] = {0, 0, 0, 0};
  int col9, len;
  word32 diffMC_list[DIFF_MC_MAX];
  word32 diff_col = 0;
  
  /* fault position and value known */
  if (row8 != -1 && col8 != -1 && fault != -1) {
    tmp[row8] = fault;
    mixColumn(tmp);
    diff_col = bytes_to_word(tmp);
  }
  
  for (col9 = 0; col9 < 4; col9++) {
    r8_get_diffMC(col8, diff_col, col9, diffMC_list, &len);
    
    cand_len[col9] = k10_cand_from_diffMC(ct, fct, col9, diffMC_list, len, candidates[col9]);
  }
}

int r8_exhaustive_search(const byte pt0[16], const byte ct0[16],
                         const byte ct[16], const byte fct[16],
                         const int row8, const int col8, const int fault,
                         const word32 candidates[4][CAND_MAX],
                         const int cand_len[4], byte masterkey[16]) {
  int i, j, k, l, ii;
  int found = 0;
  byte subkey10[16];
  byte subkey9[16];
  byte subkeys[176];
  byte cttmp[16];
  byte fcttmp[16];
  byte ctcmp[16];
  byte diff[4];
  
#ifdef _OPENMP
#pragma omp parallel for private(subkey10,subkey9,cttmp,fcttmp,j,k,l,ii,diff) shared(found)
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
          
          k9_from_k10(subkey10, subkey9);
          
          for (ii = 0; ii < 16; ii++) {
            cttmp[ii]  = ct[ii]  ^ subkey10[ii];
            fcttmp[ii] = fct[ii] ^ subkey10[ii];
          }
          invShiftRows(cttmp);
          invSubBytes(cttmp);
          invShiftRows(fcttmp);
          invSubBytes(fcttmp);      
          for (ii = 0; ii < 16; ii++) {
            cttmp[ii]  ^= subkey9[ii];
            fcttmp[ii] ^= subkey9[ii];
          }
          invMixColumns(cttmp);
          invMixColumns(fcttmp);
          
          for (ii = 0; ii < 4; ii++) {
            diff[ii] = invsbox[cttmp[POSITIONS[col8][ii]]]
              ^ invsbox[fcttmp[POSITIONS[col8][ii]]];
          }
          
          invMixColumn(diff);
          
          /* tests to validate if key candidate is consistent with the fault */
          if (diff[0] != 0) {
            if (diff[1] != 0 || diff[2] != 0 || diff[3] != 0 ||
                row8 > 0 || (fault != -1 && fault != diff[0])) {
              continue;
            }
          } else if (diff[1] != 0) {
            if (diff[2] != 0 || diff[3] != 0 || (row8 != -1 && row8 != 1) ||
                (fault != -1 && fault != diff[1])) {
              continue;
            }
          } else if (diff[2] != 0) {
            if (diff[3] != 0 || (row8 != -1 && row8 != 2) ||
                (fault != -1 && fault != diff[2])) {
              continue;
            }
          } else {
            if ((row8 != -1 && row8 != 3) ||
                (fault != -1 && fault != diff[3])) {
              continue;
            }
          }
          
          /* one final test if previous tests passed */
          reverseKeyExpansion(subkey10, subkeys);
          encrypt_aes(pt0, ctcmp, subkeys, AES_ROUNDS_128);
          
          if (memcmp(ct0, ctcmp, 16) == 0) {
            memcpy(masterkey, subkeys, 16);
            found = 1;
          }
        } /* end for l */
      } /* end for k */
    } /* end for j */
  } /* end for i */
  return found;
}

/*
 * return value
 *  0: not found
 *  1: found
 * -1: error (nb_cand = 0)
 */
int r8_key_recovery_single_ct(const byte pt0[16], const byte ct0[16],
                              const byte ct[16], const byte fct[16],
                              const int fault_pos, const int fault,
                              byte masterkey[16]) {
  int i, col8;
  int cand_len[4];
  int found = -1;
  int row8 = -1;
  int col8_start = 0;
  int col8_end = 4;
  long int nb_cand;
  word32 candidates[4][CAND_MAX];
  
  if (fault_pos >= 0 && fault_pos < 16) {
    row8 = fault_pos % 4;
    col8_start = fault_pos / 4;
    col8_end = col8_start + 1;
  }
  
  for (col8 = col8_start; col8 < col8_end; col8++) {
    r8_find_candidates(ct, fct, row8, col8, fault, candidates, cand_len);
    
    nb_cand = 1;
    for (i = 0; i < 4; i++) {
      nb_cand *= (long int)cand_len[i];
    }
    
    printf("Hypothesis: fault in column %d\n"
           "Number of candidates for positions  0, 13, 10,  7: %d\n"
           "                                    4,  1, 14, 11: %d\n"
           "                                    8,  5,  2, 15: %d\n"
           "                                   12,  9,  6,  3: %d\n"
           "Number of Master Key candidates: %ld\n",
           col8, cand_len[0], cand_len[1], cand_len[2], cand_len[3], nb_cand);
    
    if (nb_cand > 0) {
      found = r8_exhaustive_search(pt0, ct0, ct, fct, row8, col8, fault,
                                   candidates, cand_len, masterkey);
    }
    if (found == 1) {
      break;
    }
  }
  return found;
}

/*
 * In case of several (ct,fct) pairs, we only do intersections
 * of candidates followed by exhaustive search
 * return value:
 *  0: not found
 *  1: found
 * -1: error (nb_cand = 0)
 */
int r8_key_recovery(const byte pt0[16], const byte ct0[16],
                    const byte ct_list[][16], const byte fct_list[][16],
                    const int fault_pos_list[PAIRS_MAX],
                    const int fault_list[PAIRS_MAX], const int fct_len,
                    byte masterkey[16]) {
  int i, j;
  int cand_tmp_len[4], cand_len[4];
  int found = -1;
  int row8 = -1;
  int col8 = -1;
  long int nb_cand;
  word32 candidates[4][CAND_MAX];
  word32 cand_tmp[4][CAND_MAX];
  
  /* we first get candidates for a faulty ciphertext */
  if (fault_pos_list[0] >= 0 && fault_pos_list[0] < 16) {
    row8 = fault_pos_list[0] % 4;
    col8 = fault_pos_list[0] / 4;
  }
  
  r8_find_candidates(ct_list[0], fct_list[0], row8, col8, fault_list[0],
                     candidates, cand_len);
  
  /* we reduce the candidates with other pairs (ct,fct) */
  for (i = 1; i < fct_len; i++) {
    row8 = -1;
    col8 = -1;
    
    if (fault_pos_list[i] >= 0 && fault_pos_list[i] < 16) {
      row8 = fault_pos_list[i] % 4;
      col8 = fault_pos_list[i] / 4;
    }
    
    r8_find_candidates(ct_list[i], fct_list[i], row8, col8, fault_list[i],
                       cand_tmp, cand_tmp_len);
    
    /* intersection with previous candidates */
    for (j = 0; j < 4; j++) {
      intersection(candidates[j], &cand_len[j], cand_tmp[j], cand_tmp_len[j]);
    }
  }
  
  nb_cand = 1;
  for (i = 0; i < 4; i++) {
    nb_cand *= (long int)cand_len[i];
  }
  
  printf("Number of candidates for positions  0, 13, 10,  7: %d\n"
         "                                    4,  1, 14, 11: %d\n"
         "                                    8,  5,  2, 15: %d\n"
         "                                   12,  9,  6,  3: %d\n"
         "Number of Master Key candidates: %ld\n",
         cand_len[0], cand_len[1], cand_len[2], cand_len[3], nb_cand);
  
  if (nb_cand > 0) {
    found = exhaustive_search(pt0, ct0, candidates, cand_len, masterkey);
  }
  return found;
}
