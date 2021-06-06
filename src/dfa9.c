#include <stdio.h>
#include <stdint.h>
#include "aes.h"
#include "dfa.h"

/*
 * find which column the fault occured
 */
int find_faulty_column(const byte ct[16], const byte fct[16]) {
  int i;
  int column = -1;
  int ctr = 0;
  int nzpos[4];
  
  for (i = 0; i < 16; i++) {
    if ((ct[i] ^ fct[i]) != 0) {
      if (ctr != i/4) { break; }
      nzpos[ctr++] = i;
    }
  }
  if (ctr == 4) {
    if (nzpos[0] == 0 && nzpos[1] == 7 && nzpos[2] == 10 && nzpos[3] == 13) {
      column = 0;
    }
    else if (nzpos[0] == 1 && nzpos[1] == 4 && nzpos[2] == 11 && nzpos[3] == 14) {
      column = 1;
    }
    else if (nzpos[0] == 2 && nzpos[1] == 5 && nzpos[2] == 8 && nzpos[3] == 15) {
      column = 2;
    }
    else if (nzpos[0] == 3 && nzpos[1] == 6 && nzpos[2] == 9 && nzpos[3] == 12) {
      column = 3;
    }
  }
  return column;
}

int r9_get_diffMC(const byte ct[16], const byte fct[16],
                  const int fault_pos, const int fault, const int bitflip,
                  word32 diffMC_list[DIFF_MC_MAX], int *len, int *col) {
  int i, fault_len;
  int row = -1;
  int fault_list[255];
  
  /* find column where the fault occured */
  *col = find_faulty_column(ct, fct);
  if (*col == -1) { return -1; }
  
  /* check consistence with column if fault_pos is given */
  if (fault_pos != -1) {
    if (fault_pos / 4 == *col) {
      row = fault_pos % 4;
    }
    else {
      fprintf(stderr, "Fault position implies fault in column %d\n"
              "but ciphertext indicates column %d\n",
              fault_pos / 4, *col);
    }
  }
  
  /* construct list of faults ("bitflip" overtakes fault value) */
  if (bitflip) {
    for (i = 0; i < 8 ; i++) {
      fault_list[i] = 1 << i;
    }
    fault_len = 8;
  }
  else if (fault != -1) {
    fault_list[0] = fault;
    fault_len = 1;
  }
  else {
    for (i = 0; i < 255; i++) {
      fault_list[i] = i + 1;
    }
    fault_len = 255;
  }
  
  /* construct the MC differences table */
  *len = get_diff_MC(row, fault_list, fault_len, diffMC_list);
  
  return 0;
}

int r9_find_candidates(const byte ct[16], const byte fct[16],
                       const int fault_pos, const int fault,
                       const int bitflip, word32 candidates[CAND_MAX],
                       int *cand_len, int *col) {
  word32 diffMC_list[DIFF_MC_MAX];
  int len;
  int err;
  
  *cand_len = 0;
  
  /* get table of differences MC */
  err = r9_get_diffMC(ct, fct, fault_pos, fault, bitflip, diffMC_list, &len, col);
  if (err != 0) { return -1; }
  
  /* find candidates for 4 bytes of K10 */
  *cand_len = k10_cand_from_diffMC(ct, fct, *col, diffMC_list, len, candidates);
  
  return 0;
}

/*
 * return value:
 *  0: not found
 *  1: found
 * -1: error
 */
int r9_key_recovery(const byte pt[16], const byte ct[16],
                    const byte ct_list[][16], const byte fct_list[][16],
                    const int fault_pos_list[PAIRS_MAX],
                    const int fault_list[PAIRS_MAX], const int fct_len,
                    const int bitflip, byte masterkey[16]) {
  int i, j, column;
  int cand_tmp_len;
  int cand_len[4] = {-1, -1, -1, -1};
  int err = -1;
  int found = -1;
  long int nb_cand;
  word32 candidates[4][CAND_MAX];
  word32 cand_tmp[CAND_MAX];
  
  for (i = 0; i < fct_len; i++) {
    /* we first get candidates for a faulty ciphertext */
    err = r9_find_candidates(ct_list[i], fct_list[i], fault_pos_list[i],
                             fault_list[i], bitflip,
                             cand_tmp, &cand_tmp_len, &column);
    if (err) {
      fprintf(stderr, "Error: faulty ciphertext %d incompatible\n", i);
      continue;
    }
    
    /* first fct with fault in "column" */
    if (cand_len[column] == -1) {
      for (j = 0; j < cand_tmp_len; j++) {
        candidates[column][j] = cand_tmp[j];
      }
      cand_len[column] = cand_tmp_len;
    }
    /* intersection with previous candidates for this column */
    else {
      intersection(candidates[column], &cand_len[column],
                   cand_tmp, cand_tmp_len);
    }
  }
  
  for (i = 0; i < 4; i++) {
    if (cand_len[i] == -1) {
      cand_len[i] = 0;
      fprintf(stderr, "No ciphertext for diagonal %d\n", i);
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
    found = exhaustive_search(pt, ct, candidates, cand_len, masterkey);
  }
  return found;
}
