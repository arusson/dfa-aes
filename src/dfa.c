#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include "dfa.h"

#ifdef _OPENMP
#include "omp.h"
#endif

/**
 * Positions of first and last round key bytes
 * | 0| 4| 8|12|
 * | 1| 5| 9|13|
 * | 2| 6|10|14|
 * | 3| 7|11|15|
 */
const int POSITIONS_LAST_ROUND[4][4] = {
  {0, 13, 10, 7}, /* diagonal 0 */
  {4, 1, 14, 11}, /* diagonal 1 */
  {8, 5, 2, 15},  /* diagonal 2 */
  {12, 9, 6, 3}   /* diagonal 3 */
};
const int POSITIONS_FIRST_ROUND[4][4] = {
  {0, 5, 10, 15}, /* diagonal 0 */
  {4, 9, 14, 3}, /* diagonal 1 */
  {8, 13, 2, 7},  /* diagonal 2 */
  {12, 1, 6, 11}   /* diagonal 3 */
};

/**
 * Calculate the delta-set for columns containing a single value (fault).
 * This is done by applying AES mix column (encryption) or inverse mix column (decryption).
 *
 * inputs:
 * - row: position of the fault value (in [0, 3] or -1 if unknown)
 * - fault_list: list of fault values (up to 255 different faults)
 * - fault_len: length of the previous list
 * - decrypt: Boolean for decryption mode
 * - delta_set: delta-set (length is <= 255*4)
 *
 * output: length of the delta-set
 */
int get_delta_set(const int row, const int fault_list[255], const int fault_len, const bool decrypt,
                  uint32_t delta_set[DELTA_SET_MAX]) {
  int i, pos;
  int delta_set_len = 0;
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
      if (decrypt == true) {
        inv_mix_column(col);
      }
      else {
        mix_column(col);
      };
      delta_set[delta_set_len++] = BYTES_TO_WORD(col);
    }
  }
  return delta_set_len;
}

/**
 * Calculate candidates of a diagonal with the delta-set for last round key (encryption) or first
 * round key (decryption) 
 *
 * inputs:
 * - pair: ciphertext or plaintext pair
 * - col: column where the difference in round 9 (or round 2) is analyzed
 *        (see POSITIONS_LAST_ROUND or POSITIONS_FIRST_ROUND for the impacted diagonal
 *        in the ciphertext or plaintext)
 * - decrypt: Boolean for decryption mode
 * - delta_set: the delta-set
 * - delta_set_len: length of the delta-set
 * - candidates: list of candidates for the corresponding diagonal of last round key
 *
 * output: number of candidates for the last round key diagonal
 */
int roundkey_candidates_from_delta_set(const pair_t *pair, const int col, const bool decrypt,
                                       const uint32_t delta_set[DELTA_SET_MAX],
                                       const int delta_set_len, uint32_t candidates[CAND_MAX]) {
  int i, k0, k1, k2, k3;
  int cand_len = 0;
  uint8_t diff, good[4], faulty[4];
  const uint8_t *box;
  const int (*positions)[4];

  if (decrypt == true) {
    box = sbox;
    positions = POSITIONS_FIRST_ROUND;
  }
  else {
    box = invsbox;
    positions = POSITIONS_LAST_ROUND;
  };

  /* copy the 4 bytes of ct and fct that differ */
  for (i = 0; i < 4; i++) {
    good[i] = pair->ct[positions[col][i]];
    faulty[i] = pair->fct[positions[col][i]];
  }

  /* construct list of quadruplets candidates: */
  /* for each MC difference possible, find which (k0, k1, k2, k3) corresponds */
  for (i = 0; i < delta_set_len; i++) {
    for (k0 = 0; k0 < 256; k0++) {
      diff = box[good[0] ^ (uint8_t)k0] ^ box[faulty[0] ^ (uint8_t)k0];
      if (diff != TAKEBYTE(delta_set[i], 0)) {
        continue;
      }
      for (k1 = 0; k1 < 256; k1++) {
        diff = box[good[1] ^ (uint8_t)k1] ^ box[faulty[1] ^ (uint8_t)k1];
        if (diff != TAKEBYTE(delta_set[i], 1)) {
          continue;
        }
        for (k2 = 0; k2 < 256; k2++) {
          diff = box[good[2] ^ (uint8_t)k2] ^ box[faulty[2] ^ (uint8_t)k2];
          if (diff != TAKEBYTE(delta_set[i], 2)) {
            continue;
          }
          for (k3 = 0; k3 < 256; k3++) {
            diff = box[good[3] ^ (uint8_t)k3] ^ box[faulty[3] ^ (uint8_t)k3];
            if (diff != TAKEBYTE(delta_set[i], 3)) {
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
 * Run an exhaustive search of the last round key when the analysis is done.
 * If a known plaintext is provided, then the key is tested with an AES encryption.
 *
 * Generally used when the number of candidates for each diagonal of the last roud key
 * is small (e.g., two ciphertext pairs for each diagonal if the fault occurred in round 9,
 * or two ciphertext pairs if the fault occurred in round 8).
 *
 * This functions returns the number of keys.
 */
int exhaustive_search_encryption(const uint32_t candidates[4][CAND_MAX],
                                 const int candidates_len[4], const known_pt_ct_t *known_pt_ct,
                                 uint8_t masterkeys[KEYS_MAX][16]) {
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
          if (known_pt_ct->is_some) {
            encrypt_aes(known_pt_ct->pt, ctcmp, subkeys);
            if (memcmp(known_pt_ct->ct, ctcmp, 16) == 0) {
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

/**
 * Run an exhaustive search of the first round key when the analysis is done.
 * If a known plaintext and ciphertext are provided, then the key is tested with an AES encryption.
 *
 * Generally used when the number of candidates for each diagonal of the first roud key
 * is small (e.g., two pairs for each diagonal if the fault occurred in round 2).
 *
 * This functions returns the number of keys.
 */
int exhaustive_search_decryption(const uint32_t candidates[4][CAND_MAX],
                                 const int candidates_len[4], const known_pt_ct_t *known_pt_ct,
                                 uint8_t masterkeys[KEYS_MAX][16]) {
  int i, j, k, l;
  uint8_t masterkey[16];
  uint8_t subkeys[176];
  uint8_t ctcmp[16];
  int found = 0;
  int nkeys = 0;

#ifdef _OPENMP
#pragma omp parallel for private(masterkey,subkeys,ctcmp,j,k,l) shared(found,nkeys)
#endif
  for (i = 0; i < candidates_len[0]; i++) {
    if (found) {
      /* abort search for each thread */
      continue;
    }
    masterkey[0]  = TAKEBYTE(candidates[0][i], 0);
    masterkey[5]  = TAKEBYTE(candidates[0][i], 1);
    masterkey[10] = TAKEBYTE(candidates[0][i], 2);
    masterkey[15] = TAKEBYTE(candidates[0][i], 3);

    for (j = 0; j < candidates_len[1]; j++) {
      masterkey[4]  = TAKEBYTE(candidates[1][j], 0);
      masterkey[9]  = TAKEBYTE(candidates[1][j], 1);
      masterkey[14] = TAKEBYTE(candidates[1][j], 2);
      masterkey[3]  = TAKEBYTE(candidates[1][j], 3);

      for (k = 0; k < candidates_len[2]; k++) {
        masterkey[8]  = TAKEBYTE(candidates[2][k], 0);
        masterkey[13] = TAKEBYTE(candidates[2][k], 1);
        masterkey[2]  = TAKEBYTE(candidates[2][k], 2);
        masterkey[7]  = TAKEBYTE(candidates[2][k], 3);

        for (l = 0; l < candidates_len[3]; l++) {
          masterkey[12] = TAKEBYTE(candidates[3][l], 0);
          masterkey[1]  = TAKEBYTE(candidates[3][l], 1);
          masterkey[6]  = TAKEBYTE(candidates[3][l], 2);
          masterkey[11] = TAKEBYTE(candidates[3][l], 3);

          if (known_pt_ct->is_some) {
            key_expansion(masterkey, subkeys);
            encrypt_aes(known_pt_ct->pt, ctcmp, subkeys);
            if (memcmp(known_pt_ct->ct, ctcmp, 16) == 0) {
#ifdef _OPENMP
#pragma omp critical
#endif
              {
                memcpy(masterkeys[nkeys], masterkey, 16);
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
              memcpy(masterkeys[nkeys], masterkey, 16);
              nkeys++;
            }
          }
        } /* end for l */
      } /* end for k */
    } /* end for j */
  } /* end for i */
  return nkeys;
}
