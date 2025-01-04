#ifndef DFA_H_
#define DFA_H_

#include <stdint.h>
#include <stdbool.h>
#include "aes.h"

#define DFA_ROUND_8 8
#define DFA_ROUND_9 9
#define DIFF_MC_MAX 1020
#define CAND_MAX 2000
#define PAIRS_MAX 20
#define KEYS_MAX 65536

#define BYTES_TO_WORD(a) *(uint32_t *)(a)
#define TAKEBYTE(w,n) (uint8_t)(((w)>>(8*n)) & 255)

int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;

extern const int POSITIONS[4][4];

typedef struct Pair {
  uint8_t ct[16];
  uint8_t fct[16];
  int fault_pos;
  int fault_value;
  bool bitflip;
} pair_t;

typedef struct KnownPt {
  uint8_t pt[16];
  uint8_t ct[16];
  bool is_some;
} known_pt_t;

/* utils */
int readfile(const char *filename, pair_t pairs[PAIRS_MAX], int *npairs, known_pt_t *known_pt);
void print_hex(const uint8_t *buffer, const int len);
void print_pair_info(const pair_t *pair);
void print_number_candidates_line(const int num, const int col);
void print_number_candidates(const int candidates_len[4], const long nb_cand);

/* dfa */
int get_diff_mc(
  const int row,
  const int fault_list[255],
  const int fault_len,
  uint32_t list_diff[DIFF_MC_MAX]
);
int k10_cand_from_diff_mc(
  const pair_t *pair,
  const int col,
  const uint32_t diff_mc_list[DIFF_MC_MAX],
  const int diff_mc_len,
  uint32_t candidates[CAND_MAX]
);
void intersection(uint32_t *list1, int *len1, const uint32_t *list2, const int len2);
void reverse_key_expansion(const uint8_t subkey10[16], uint8_t subkeys[176]);
void k9_from_k10(const uint8_t subkey10[16], uint8_t subkey9[16]);
int exhaustive_search(
  const uint32_t candidates[4][CAND_MAX],
  const int candidates_len[4],
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
);

/* dfa round 9 */
int r9_key_recovery(
  const pair_t pairs[PAIRS_MAX],
  const int npairs,
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
);

/* dfa round 8 */
int r8_key_recovery(
  pair_t pairs[PAIRS_MAX],
  const int npairs,
  const known_pt_t *known_pt,
  uint8_t masterkeys[KEYS_MAX][16]
);
#endif
