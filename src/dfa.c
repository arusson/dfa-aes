#include <stdint.h>
#include <string.h>
#include "dfa.h"

#ifdef _OPENMP
#include "omp.h"
#endif

/**
 * Positions of the last round key bytes
 * | 0| 4| 8|12|
 * | 1| 5| 9|13|
 * | 2| 6|10|14|
 * | 3| 7|11|15|
 */
const int POSITIONS[4][4] = {
  {0, 13, 10, 7}, /* diagonal 0 */
  {4, 1, 14, 11}, /* diagonal 1 */
  {8, 5, 2, 15},  /* diagonal 2 */
  {12, 9, 6, 3}   /* diagonal 3 */
};

/**
 * Calculate the delta-set for columns containing a single value (fault).
 * This is done by applying AES mix column.
 *
 * inputs:
 * - row: position of the fault value (in [0, 3] or -1 if unknown)
 * - fault_list: list of fault values (up to 255 different faults)
 * - fault_len: length of the previous list
 * - list_diff: delta-set (length is <= 255*4)
 *
 * output: length of the delta-set
 */
int get_diff_mc(
  const int row,
  const int fault_list[255],
  const int fault_len,
  uint32_t list_diff[DIFF_MC_MAX]
) {
  int i, pos;
  int list_diff_len = 0;
  int row_start = 0;
  int row_end = 4;
  uint8_t col[4] = {0, 0, 0, 0};

  if (row != -1) {
    row_start = row;
    row_end = row + 1;
  }

  for (pos = row_start; pos < row_end; pos++) {
    for (i = 0; i < fault_len; i++) {
      memset(col, 0, 4);
      col[pos] = (uint8_t)fault_list[i];
      mix_column(col);
      list_diff[list_diff_len++] = BYTES_TO_WORD(col);
    }
  }
  return list_diff_len;
}

/**
 * Calculate candidates of a diagonal for last round key with the delta-set.
 *
 * inputs:
 * - pair: ciphertext pair
 * - col: column where the difference in round 9 is analyzed
 *        (see POSITIONS for the impacted diagonal in the ciphertext)
 * - diff_mc_list: the delta-set
 * - diff_mc_len: length of the delta-set
 * - candidates: list of candidates for the corresponding diagonal of last round key
 *
 * output: number of candidates for the last round key diagonal
 */
int k10_cand_from_diff_mc(
  const pair_t *pair,
  const int col,
  const uint32_t diff_mc_list[DIFF_MC_MAX],
  const int diff_mc_len,
  uint32_t candidates[CAND_MAX]
) {
  int i, k0, k1, k2, k3;
  int cand_len = 0;
  uint8_t diff, good[4], faulty[4];

  /* copy the 4 bytes of ct and fct that differ */
  for (i = 0; i < 4; i++) {
    good[i] = pair->ct[POSITIONS[col][i]];
    faulty[i] = pair->fct[POSITIONS[col][i]];
  }

  /* construct list of quadruplets candidates: */
  /* for each MC difference possible, find which (k0, k1, k2, k3) corresponds */
  for (i = 0; i < diff_mc_len; i++) {
    for (k0 = 0; k0 < 256; k0++) {
      diff = invsbox[good[0] ^ (uint8_t)k0] ^ invsbox[faulty[0] ^ (uint8_t)k0];
      if (diff != TAKEBYTE(diff_mc_list[i], 0)) {
        continue;
      }
      for (k1 = 0; k1 < 256; k1++) {
        diff = invsbox[good[1] ^ (uint8_t)k1] ^ invsbox[faulty[1] ^ (uint8_t)k1];
        if (diff != TAKEBYTE(diff_mc_list[i], 1)) {
          continue;
        }
        for (k2 = 0; k2 < 256; k2++) {
          diff = invsbox[good[2] ^ (uint8_t)k2] ^ invsbox[faulty[2] ^ (uint8_t)k2];
          if (diff != TAKEBYTE(diff_mc_list[i], 2)) {
            continue;
          }
          for (k3 = 0; k3 < 256; k3++) {
            diff = invsbox[good[3] ^ (uint8_t)k3] ^ invsbox[faulty[3] ^ (uint8_t)k3];
            if (diff != TAKEBYTE(diff_mc_list[i], 3)) {
              continue;
            }
            candidates[cand_len++] = ((uint32_t)k3 << 24)
              | ((uint32_t)k2 << 16)
              | ((uint32_t)k1 << 8)
              | (uint32_t)k0;
          } /* end for k3 */
        } /* end for k2 */
      } /* end for k1 */
    } /* end for k0 */
  } /* end for i */

  return cand_len;
}

/**
 * Simple intersection of two lists.
 * The first one is overwritten with all common elements.
 */
void intersection(uint32_t *list1, int *len1, const uint32_t *list2, const int len2) {
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

/**
 * Reconstruct the AES round keys from the last one
 */
void reverse_key_expansion(const uint8_t subkey10[16], uint8_t subkeys[176]) {
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

/**
 * Reconstruct the penultimate round key from the last one
 */
void k9_from_k10(const uint8_t subkey10[16], uint8_t subkey9[16]) {
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

/**
 * Run an exhaustive search of the last round key when the analysis is done.
 * If a known plaintext is provided, then the key is tested with an AES encryption.
 *
 * Generally used when the number of candidates for each diagonal of the last roud key
 * is small (e.g., two ciphertext pairs for each diagonal if the fault occurred in round 9,
 * or two ciphertext pairs if the fault occurred in round 8).
 *
 * This functions returns the number of keys.
 */
int exhaustive_search(
  const uint32_t candidates[4][CAND_MAX],
  const int candidates_len[4],
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
) {
  int i, j, k, l;
  uint8_t subkey10[16];
  uint8_t subkeys[176];
  uint8_t ctcmp[16];
  int found = 0;
  int nkeys = 0;

#ifdef _OPENMP
#pragma omp parallel for private(subkey10,subkeys,ctcmp,j,k,l) shared(found,nkeys)
#endif
  for (i = 0; i < candidates_len[0]; i++) {
    if (found) {
      /* abort search for each thread */
      continue;
    }
    subkey10[0]  = TAKEBYTE(candidates[0][i], 0);
    subkey10[13] = TAKEBYTE(candidates[0][i], 1);
    subkey10[10] = TAKEBYTE(candidates[0][i], 2);
    subkey10[7]  = TAKEBYTE(candidates[0][i], 3);

    for (j = 0; j < candidates_len[1]; j++) {
      subkey10[4]  = TAKEBYTE(candidates[1][j], 0);
      subkey10[1]  = TAKEBYTE(candidates[1][j], 1);
      subkey10[14] = TAKEBYTE(candidates[1][j], 2);
      subkey10[11] = TAKEBYTE(candidates[1][j], 3);

      for (k = 0; k < candidates_len[2]; k++) {
        subkey10[8]  = TAKEBYTE(candidates[2][k], 0);
        subkey10[5]  = TAKEBYTE(candidates[2][k], 1);
        subkey10[2]  = TAKEBYTE(candidates[2][k], 2);
        subkey10[15] = TAKEBYTE(candidates[2][k], 3);

        for (l = 0; l < candidates_len[3]; l++) {
          subkey10[12] = TAKEBYTE(candidates[3][l], 0);
          subkey10[9]  = TAKEBYTE(candidates[3][l], 1);
          subkey10[6]  = TAKEBYTE(candidates[3][l], 2);
          subkey10[3]  = TAKEBYTE(candidates[3][l], 3);

          reverse_key_expansion(subkey10, subkeys);
          if (known_pt->is_some) {
            encrypt_aes(known_pt->pt, ctcmp, subkeys);
            if (memcmp(known_pt->ct, ctcmp, 16) == 0) {
#ifdef _OPENMP
#pragma omp critical
#endif
              {
                memcpy(masterkeys[nkeys], subkeys, 16);
                found = 1;
                nkeys = 1;
              }
            }
          }
          else {
#ifdef _OPENMP
#pragma omp critical
#endif
            {
              memcpy(masterkeys[nkeys], subkeys, 16);
              nkeys++;
            }
          }
        } /* end for l */
      } /* end for k */
    } /* end for j */
  } /* end for i */
  return nkeys;
}
