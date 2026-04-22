#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "dfa.h"

/**
 * These flags facilitates to find if only 4 bytes of a "diagonal" are different
 * between two blocks.
 * 
 * Example:
 *     0x2481 with LSB first -> 1000 0001 0010 0100
 *     which describes the position in each column
 */
uint16_t FLAGS_POSITIONS_ENCRYPTION[4] = {0x2481, 0x4812, 0x8124, 0x1248};
uint16_t FLAGS_POSITIONS_DECRYPTION[4] = {0x8421, 0x4218, 0x2184, 0x1842};

/**
 * Find which column the fault occurred in an encryption or decryption.
 *
 * It is based on the 4 bytes that differ in the ciphertexts/plaintexts.
 * Returns -1 if not found.
 */
static int find_faulty_column(const pair_t *pair, uint16_t flags[4]) {
  size_t i;
  uint16_t flag = 0;
  int column = -1;

  for (i = 0; i < 16; i++) {
    if ((pair->ct[i] ^ pair->fct[i]) != 0) {
      flag |= (1 << i);
    }
  }

  i = 0;
  while (i <= 3) {
    if (flag == flags[i]) {
      column = i;
      break;
    }
    i += 1;
  }
  
  return column;
}

/**
 * Return fault row if the fault position is known.
 * An inconsistent fault is ignored.
 * Default value is -1 (fault position unknown).
 */
static int get_fault_row(const pair_t *pair, int col) {
  int row = -1;
  if (pair->fault_pos != -1) {
    if (pair->fault_pos / 4 == col) {
      row = pair->fault_pos % 4;
    }
    else {
      fprintf(stderr,
              "[!] Fault position implies fault in column %d\nbut the data indicates column %d\n",
              pair->fault_pos / 4, col);
    }
  }
  return row;
}

/**
 * Construct a list of faults.
 * - fault given as input: 1 fault
 * - bitflip: 8 faults
 * - default: 255 faults
 */
static int get_fault_list(const pair_t *pair, int fault_list[255]) {
  size_t i;
  size_t fault_len;

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

  return fault_len;
}

/**
 * Calculate the delta-set for one ciphertext pair.
 * It is expected that the pair differs only in a diagonal.
 *
 * Returns the length of the delta-set (0 if the ciphertext pair
 * does not match criterias for a fault in round 9).
 */
static int r1_r9_get_delta_set(const pair_t *pair, const bool decrypt,
                            uint32_t delta_set[DELTA_SET_MAX], int *col) {
  int fault_len, len, row;
  int fault_list[255];

  /* find column where the fault occurred */
  if (decrypt == true) {
    *col = find_faulty_column(pair, FLAGS_POSITIONS_DECRYPTION);
  }
  else {
    *col = find_faulty_column(pair, FLAGS_POSITIONS_ENCRYPTION);
  }
  if (*col == -1) {
    return 0;
  }

  /* check consistence with column if fault_pos is given */
  row = get_fault_row(pair, *col);

  /* construct list of faults ("bitflip" overtakes fault value) */
  fault_len = get_fault_list(pair, fault_list);

  /* construct the delta-set */
  len = get_delta_set(row, fault_list, fault_len, decrypt, delta_set);

  return len;
}

/**
 * Calculate candidates for a ciphertext pair
 * and get column where the fault occurred.
 *
 * Returns the number of candidates.
 */
static int r1_r9_find_candidates(const pair_t *pair, const bool decrypt,
                                 uint32_t candidates[CAND_MAX], int *col) {
  uint32_t delta_set[DELTA_SET_MAX];
  int candidates_len;
  int delta_set_len;

  /* get delta-set */
  delta_set_len = r1_r9_get_delta_set(pair, decrypt, delta_set, col);
  if (delta_set_len == 0) {
    return 0;
  }

  /* find candidates for 4 bytes of K10 */
  candidates_len = roundkey_candidates_from_delta_set(pair, *col, decrypt, delta_set, delta_set_len,
                                                      candidates);

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
int r1_r9_key_recovery(const pair_t pairs[PAIRS_MAX], const int npairs,
                       const known_pt_ct_t *known_pt_ct, const bool decrypt,
                       uint8_t masterkeys[KEYS_MAX][16]) {
  int i, j, column, cand_tmp_len;
  int candidates_len[4] = {-1, -1, -1, -1};
  int nkeys = 0;
  long nb_cand;
  uint32_t candidates[4][CAND_MAX];
  uint32_t cand_tmp[CAND_MAX];

  /* process all ciphertext pairs */
  for (i = 0; i < npairs; i++) {
    fprintf(stderr, "[*] Processing pair %d out of %d:\n", i + 1, npairs);
    print_pair_info(&pairs[i]);
    cand_tmp_len = r1_r9_find_candidates(&pairs[i], decrypt, cand_tmp, &column);
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
    print_number_candidates_line(candidates_len[column], column, decrypt);
  }

  /* calculate the number of candidates for the last round key*/
  for (i = 0; i < 4; i++) {
    if (candidates_len[i] == -1) {
      candidates_len[i] = 0;
      fprintf(stderr, "[!] No ciphertext/plaintext for diagonal %d\n", i);
    }
  }
  nb_cand = 1;
  for (i = 0; i < 4; i++) {
    nb_cand *= (long)candidates_len[i];
  }
  print_number_candidates(candidates_len, nb_cand, decrypt);

  /* final search */
  if (nb_cand > 0) {
    if (!known_pt_ct->is_some && nb_cand > KEYS_MAX) {
      fprintf(stderr,
              "[!] Analysis aborted: too many candidates to save (maximum: %d)\n"
              "[!] Please provide a known plaintext or other ciphertext pairs\n",
              KEYS_MAX);
      exit(EXIT_FAILURE);
    }
    if (known_pt_ct->is_some) {
      fprintf(stderr, "[*] Filtering with known plaintext and ciphertext\n");
    }
    if (decrypt == true) {
      nkeys = exhaustive_search_decryption(candidates, candidates_len, known_pt_ct, masterkeys);
    }
    else {
      nkeys = exhaustive_search_encryption(candidates, candidates_len, known_pt_ct, masterkeys);
    }
  }
  return nkeys;
}
