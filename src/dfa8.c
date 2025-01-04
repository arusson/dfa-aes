#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include "dfa.h"

#ifdef _OPENMP
#include "omp.h"
#endif

/**
 * Table look-up to find if a byte contains a single bit.
 */
static uint8_t BITFLIP[256] = {
  0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Calculate the delta-set for a specific column in round 9.
 *
 * A fault in round 8 has an impact on four bytes in round 9.
 * For each of those, the analysis can be performed as if the fault occurred there.
 * The "fault" in round 9 can be any of 255 possible values.
 * However, if the fault in round 8 is precisely known, it can be limited
 * to 127 "fault" values.
 *
 * inputs:
 * - col8: if known, the column where the fault occurred in round 8
 * - col9: column of round 9, useful only to know which row is affected
 *         when the fault position in round 8 is known
 * - diff_col: output of mix column of the specific fault in round 8 if known
 * - diff_mc_list: the delta-set
 *
 * output: length of the delta-set
 */
static int r8_get_diff_mc(
  const int col8,
  const int col9,
  const uint32_t diff_col,
  uint32_t diff_mc_list[DIFF_MC_MAX]
) {
  int i, c1, c2, diff, len;
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
      if (c1 > c2) {
        continue;
      }
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

  /* construct the delta-set */
  len = get_diff_mc(row9, fault_list, fault_list_len, diff_mc_list);

  return len;
}

/**
 * Calculate candidates for a ciphertext pair.
 *
 * inputs:
 * - pair: ciphertext pair
 * - row8 and col8: position of the fault in round 8 if known
 * - candidates: lists of candidates for each diagonal of the last round key
 * - candidates_len: lengths of each list of candidates
 */
static void r8_find_candidates(
  const pair_t *pair,
  const int row8,
  const int col8,
  uint32_t candidates[4][CAND_MAX],
  int candidates_len[4]
) {
  uint8_t tmp[4] = {0, 0, 0, 0};
  int col9, len;
  uint32_t diff_mc_list[DIFF_MC_MAX];
  uint32_t diff_col = 0;

  /* fault position and value known (used to reduce the delta-set) */
  if (row8 != -1 && col8 != -1 && pair->fault_value != -1) {
    tmp[row8] = pair->fault_value;
    mix_column(tmp);
    diff_col = BYTES_TO_WORD(tmp);
  }

  /* get delta-set for each column in round 9, then get candidates for corresponding diagonals */
  for (col9 = 0; col9 < 4; col9++) {
    len = r8_get_diff_mc(col8, col9, diff_col, diff_mc_list);
    candidates_len[col9] = k10_cand_from_diff_mc(pair, col9, diff_mc_list, len, candidates[col9]);
  }
}

/**
 * Run an exhaustive search for the last round key.
 * A filtering is applied to check if a round key is consistent
 * with the fault: the difference of states in round 8 before mix column
 * must have a single non-null byte; if the fault position is known,
 * then this byte must be on the same position; if the fault if known,
 * it must be the same as the fault value.
 *
 * This search is made with the hypothesis that the fault occurred in column `col8`
 * (this function is called four times if the fault position is unknown).
 *
 * If the fault position is known, the number of candidates should be reduced
 * from 2^32 to around 2^8.
 * If the fault position and value are known, the number of candidates
 * shoud be very close to one.
 *
 * If a known plaintext/ciphertext is known, the key will be tested with an encryption.
 */
static int r8_exhaustive_search(
  const pair_t *pair,
  const int row8,
  const int col8,
  const uint32_t candidates[4][CAND_MAX],
  const int candidates_len[4],
  const known_pt_t *known_pt,
  uint8_t masterkeys[][16]
) {
  int i, j, k, l, ii;
  int found = 0;
  int nkeys = 0;
  int row = row8;
  alignas(16) uint32_t diff32[4];
  uint32_t masks[4] = {0xffffff00, 0xffff00ff, 0xff00ffff, 0x00ffffff};
  uint8_t subkey10[16];
  alignas(16) uint8_t subkey9[16];
  uint8_t subkeys[176];
  alignas(16) uint8_t cttmp[16];
  alignas(16) uint8_t fcttmp[16];
  alignas(16) uint8_t ctcmp[16];

#ifdef _OPENMP
#pragma omp parallel for firstprivate(row,masks) private(j,k,l,ii,subkey10,subkey9,subkeys,cttmp,fcttmp,ctcmp,diff32) shared(found,nkeys)
#endif
  for (i = 0; i < candidates_len[0]; i++) {
    if (found) {
      /* abort search for each threads */
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

          k9_from_k10(subkey10, subkey9);

          /* xor last round key (optimized as vpxor by the compiler) */
          for (ii = 0; ii < 16; ii++) {
            cttmp[ii]  = pair->ct[ii]  ^ subkey10[ii];
            fcttmp[ii] = pair->fct[ii] ^ subkey10[ii];
          }

          /* decrypt last round */
          __m128i k = _mm_load_si128((const __m128i *)subkey9);
          k = _mm_aesimc_si128(k);
          __m128i x = _mm_load_si128((const __m128i *)cttmp);
          __m128i y = _mm_load_si128((const __m128i *)fcttmp);
          x = _mm_aesdec_si128(x, k);
          y = _mm_aesdec_si128(y, k);

          /* decrypt round 9 */
          x = _mm_aesdec_si128(x, k);
          y = _mm_aesdec_si128(y, k);

          /* xor of states of ciphertext pair before mix column in round 8 */
          x = _mm_xor_si128(x, y);
          _mm_store_si128((__m128i *)diff32, x);

          /* first filter: the column must have a single non-null byte */
          /* case fault position known */
          if (row8 != -1) {
            if ((diff32[col8] & masks[row8]) != 0) {
              continue;
            }
          }
          /* case fault position unknown */
          else {
            if ((diff32[col8] & masks[0]) == 0) {
              row = 0;
            }
            else if ((diff32[col8] & masks[1]) == 0) {
              row = 1;
            }
            else if ((diff32[col8] & masks[2]) == 0) {
              row = 2;
            }
            else if ((diff32[col8] & masks[3]) == 0) {
              row = 3;
            }
            else {
              continue;
            }
          }

          /* second filter: the non-null byte must correspond to the fault (if known) */
          if (pair->fault_value != -1) {
            if (((int)(diff32[col8] >> row*8) & 0xff) != pair->fault_value) {
              continue;
            }
          }
          else if (pair->bitflip == true) {
            if (BITFLIP[(diff32[col8] >> row*8) & 0xff] == 0) {
              continue;
            }
          }

          /* very few candidates expected to reach this place */
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

/**
 * Main function for key recovery with a single ciphertext pair
 * with a fault in round 8.
 *
 * Run the analysis to find candidates for each diagonal, then run
 * an exhaustive search with filtering, with or without a known plaintext.
 */
static int r8_key_recovery_single_ct(
  const pair_t *pair,
  const int row8,
  const int col8,
  const known_pt_t *known_pt,
  uint8_t masterkeys[][16]
) {
  int i;
  int candidates_len[4];
  int nkeys = 0;
  long nb_cand;
  uint32_t candidates[4][CAND_MAX];

  /* get candidates for each diagonal of last round key */
  r8_find_candidates(pair, row8, col8, candidates, candidates_len);
  nb_cand = 1;
  for (i = 0; i < 4; i++) {
    nb_cand *= (long)candidates_len[i];
  }

  if (pair->fault_value != -1) {
    fprintf(
      stderr,
      "[*] Hypothesis: fault in column %d and fault is '0x%02x'\n",
      col8, pair->fault_value
    );
  }
  else {
    fprintf(stderr, "[*] Hypothesis: fault in column %d and fault is unknown\n", col8);
  }

  print_number_candidates(candidates_len, nb_cand);
  if (known_pt->is_some) {
    fprintf(stderr, "[*] Filtering (followed by known plaintext validation)\n");
  }
  else {
    fprintf(stderr, "[*] Filtering (without plaintext validation)\n");
  }

  /* final search */
  if (nb_cand > 0) {
    nkeys = r8_exhaustive_search(
      pair, row8, col8, candidates, candidates_len, known_pt, &masterkeys[nkeys]
    );
  }

  fprintf(stderr, "[*] Number of keys after filtering: %d\n", nkeys);

  return nkeys;
}

/*
 * In case of several ciphertext pairs, we only do intersections of candidates
 * followed by an exhaustive search common with round 9.
 */
static int r8_key_recovery_multiple_ct(
  const pair_t pairs[PAIRS_MAX],
  const int npairs,
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
) {
  int i, j;
  int cand_tmp_len[4], candidates_len[4];
  int row8 = -1;
  int col8 = -1;
  int nkeys = 0;
  long int nb_cand;
  uint32_t candidates[4][CAND_MAX];
  uint32_t cand_tmp[4][CAND_MAX];

  /* first we get candidates for a faulty ciphertext */
  if (pairs[0].fault_pos >= 0 && pairs[0].fault_pos < 16) {
    row8 = pairs[0].fault_pos % 4;
    col8 = pairs[0].fault_pos / 4;
  }

  r8_find_candidates(&pairs[0], row8, col8, candidates, candidates_len);

  /* we reduce the candidates with other pairs (ct,fct) */
  for (i = 1; i < npairs; i++) {
    row8 = -1;
    col8 = -1;

    if (pairs[i].fault_pos >= 0 && pairs[i].fault_pos < 16) {
      row8 = pairs[i].fault_pos % 4;
      col8 = pairs[i].fault_pos / 4;
    }

    r8_find_candidates(&pairs[i], row8, col8, cand_tmp, cand_tmp_len);

    /* intersection with previous candidates */
    for (j = 0; j < 4; j++) {
      intersection(candidates[j], &candidates_len[j], cand_tmp[j], cand_tmp_len[j]);
    }
  }

  nb_cand = 1;
  for (i = 0; i < 4; i++) {
    nb_cand *= (long int)candidates_len[i];
  }

  print_number_candidates(candidates_len, nb_cand);

  if (nb_cand > 0) {
    nkeys = exhaustive_search(candidates, candidates_len, known_pt, masterkeys);
  }
  return nkeys;
}

/**
 * Main function for key recovery with a fault in round 8.
 * Depending of the number of ciphertext pairs, it will call one
 * of the previous functions.
 *
 * For a single ciphertext pair:
 * - if the fault is unknown, the key recovery will be attempted four times
 *   (one for each assumption for the column where the fault occurred)
 * - if the fault is a bitflip, it will be performed for each of the eight bit positions
 * - if the fault position and value are known: a single key recovery.
 *
 * The last one should give a result very fast.
 * For the other cases, it depends of the number of cores available,
 * but it can be less than a minute for an unknown position and value.
 */
int r8_key_recovery(
  pair_t pairs[PAIRS_MAX],
  const int npairs,
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
) {
  pair_t *pair;
  int bit, col8;
  int row8 = -1;
  int col8_start = 0;
  int col8_end = 4;
  int nkeys = 0;

  /* processing multiple ciphertext pairs */
  if (npairs > 1) {
    return r8_key_recovery_multiple_ct(pairs, npairs, known_pt, masterkeys);
  }

  /* processing a single ciphertext pair */
  pair = &pairs[0];
  fprintf(stderr, "[*] Processing a single ciphertext pair:\n");
  print_pair_info(pair);

  /* get column where the fault occurred if known */
  if (pair->fault_pos >= 0 && pair->fault_pos < 16) {
    row8 = pair->fault_pos % 4;
    col8_start = pair->fault_pos / 4;
    col8_end = col8_start + 1;
  }

  /* if fault is a bitflip (position known), the analysis is run 8 times
   * with each bitflip possible considered as a fault value:
   * should reduce by half compared to an unknown fault value
   */
  for(col8 = col8_start; col8 < col8_end; col8++) {
    /* if fault is a bitflip, run analysis for the 8 bitflips possible */
    if (pair->bitflip == true && pair->fault_pos != -1) {
      for (bit = 1; bit < 256; bit <<= 1) {
        pair->fault_value = bit;
        nkeys += r8_key_recovery_single_ct(pair, row8, col8, known_pt, &masterkeys[nkeys]);
        if (known_pt->is_some && nkeys == 1) {
          goto found;
        }
      }
    }
    else {
      nkeys += r8_key_recovery_single_ct(pair, row8, col8, known_pt, &masterkeys[nkeys]);
      if (known_pt->is_some && nkeys == 1) {
        goto found;
      }
    }
  }

found:
  return nkeys;
}
