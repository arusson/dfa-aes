#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "dfa.h"

/**
 * Find which column the fault occurred.
 */
static int find_faulty_column(const pair_t *pair) {
  int i;
  int column = -1;
  int ctr = 0;
  int nzpos[4] = {0};

  for (i = 0; i < 16; i++) {
    if ((pair->ct[i] ^ pair->fct[i]) != 0) {
      if (ctr != i/4) {
        break;
      }
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

/**
 * Calculate the delta-set for one ciphertext pair.
 * It is expected that the pair differs only in a diagonal.
 *
 * Returns the length of the delta-set (0 if the ciphertext pair
 * does not match criterias for a fault in round 9).
 */
static int r9_get_diff_mc(
  const pair_t *pair,
  uint32_t diff_mc_list[DIFF_MC_MAX],
  int *col
) {
  int i, fault_len, len;
  int row = -1;
  int fault_list[255];

  /* find column where the fault occurred */
  *col = find_faulty_column(pair);
  if (*col == -1) {
    return 0;
  }

  /* check consistence with column if fault_pos is given */
  if (pair->fault_pos != -1) {
    if (pair->fault_pos / 4 == *col) {
      row = pair->fault_pos % 4;
    }
    else {
      fprintf(
        stderr,
        "[!] Fault position implies fault in column %d\nbut ciphertext indicates column %d\n",
        pair->fault_pos / 4, *col
      );
    }
  }

  /* construct list of faults ("bitflip" overtakes fault value) */
  if (pair->bitflip == true) {
    for (i = 0; i < 8 ; i++) {
      fault_list[i] = 1 << i;
    }
    fault_len = 8;
  }
  else if (pair->fault_value != -1) {
    fault_list[0] = pair->fault_value;
    fault_len = 1;
  }
  else {
    for (i = 0; i < 255; i++) {
      fault_list[i] = i + 1;
    }
    fault_len = 255;
  }

  /* construct the delta-set */
  len = get_diff_mc(row, fault_list, fault_len, diff_mc_list);

  return len;
}

/**
 * Calculate candidates for a ciphertext pair
 * and get column where the fault occurred.
 *
 * Returns the number of candidates.
 */
static int r9_find_candidates(
  const pair_t *pair,
  uint32_t candidates[CAND_MAX],
  int *col
) {
  uint32_t diff_mc_list[DIFF_MC_MAX];
  int candidates_len;
  int diff_mc_len;

  /* get delta-set */
  diff_mc_len = r9_get_diff_mc(pair, diff_mc_list, col);
  if (diff_mc_len == 0) {
    return 0;
  }

  /* find candidates for 4 bytes of K10 */
  candidates_len = k10_cand_from_diff_mc(pair, *col, diff_mc_list, diff_mc_len, candidates);

  return candidates_len;
}

/**
 * The main function for the key recovery with faults in round 9.
 * Each ciphertext pair is processed and candidates for each diagonal are reduced
 * if several pairs are available for each diagonal.
 *
 * It ends with an exhaustive search for the last round key.
 * If two pairs are provided for each diagonal,
 * then one or two candidates are expected for this search.
 *
 * If a known plaintext/ciphertext is provided, the key will be checked.
 * Otherwise, if two keys or more are found, they will be written to `masterkeys`.
 */
int r9_key_recovery(
  const pair_t pairs[PAIRS_MAX],
  const int npairs,
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
) {
  int i, j, column, cand_tmp_len;
  int candidates_len[4] = {-1, -1, -1, -1};
  int nkeys = 0;
  long nb_cand;
  uint32_t candidates[4][CAND_MAX];
  uint32_t cand_tmp[CAND_MAX];

  /* process all ciphertext pairs */
  for (i = 0; i < npairs; i++) {
    fprintf(stderr, "[*] Processing ciphertext pair %d out of %d:\n", i + 1, npairs);
    print_pair_info(&pairs[i]);
    cand_tmp_len = r9_find_candidates(&pairs[i], cand_tmp, &column);
    if (cand_tmp_len == 0) {
      fprintf(stderr, "[!] This pair is ignored (incompatible)\n");
      continue;
    }

    /* first pair with fault in "column" */
    if (candidates_len[column] == -1) {
      for (j = 0; j < cand_tmp_len; j++) {
        candidates[column][j] = cand_tmp[j];
      }
      candidates_len[column] = cand_tmp_len;
    }
    /* intersection with previous candidates for this column */
    else {
      intersection(candidates[column], &candidates_len[column], cand_tmp, cand_tmp_len);
    }
    print_number_candidates_line(candidates_len[column], column);
  }

  /* calculate the number of candidates for the last round key*/
  for (i = 0; i < 4; i++) {
    if (candidates_len[i] == -1) {
      candidates_len[i] = 0;
      fprintf(stderr, "[!] No ciphertext for diagonal %d\n", i);
    }
  }
  nb_cand = 1;
  for (i = 0; i < 4; i++) {
    nb_cand *= (long)candidates_len[i];
  }
  print_number_candidates(candidates_len, nb_cand);

  /* final search */
  if (nb_cand > 0) {
    if (!known_pt->is_some && nb_cand > KEYS_MAX) {
      fprintf(
        stderr,
        "[!] Analysis aborted: too many candidates to save (maximum: %d)\n"
        "[!] Please provide a known plaintext or other ciphertext pairs\n",
        KEYS_MAX
      );
      exit(EXIT_FAILURE);
    }
    if (known_pt->is_some) {
      fprintf(stderr, "[*] Filtering with known plaintext\n");
    }
    nkeys = exhaustive_search(candidates, candidates_len, known_pt, masterkeys);
  }
  return nkeys;
}
