#ifndef DFA_H_
#define DFA_H_

#include "aes.h"

#define DIFF_MC_MAX 1020
#define CAND_MAX 2000
#define PAIRS_MAX 20

extern const int POSITIONS[4][4];

int get_diff_MC(const int row, const int fault_list[255], const int fault_len,
                word32 list_diff[DIFF_MC_MAX]);

int k10_cand_from_diffMC(const byte ct[16], const byte fct[16], const int col,
                         const word32 diffMC_list[DIFF_MC_MAX],
                         const int diffMC_len, word32 candidates[CAND_MAX]);

void intersection(word32 *list1, int *len1, const word32 *list2, const int len2);

void reverseKeyExpansion(const byte subkey10[16], byte subkeys[176]);

void k9_from_k10(const byte subkey10[16], byte subkey9[16]);

int exhaustive_search(const byte pt[16], const byte ct[16],
                      const word32 candidates[4][CAND_MAX],
                      const int cand_len[4], byte masterkey[16]);



/* attack round 9 */

int find_faulty_column(const byte ct[16], const byte fct[16]);

int r9_get_diffMC(const byte ct[16], const byte fct[16],
                  const int fault_pos, const int fault, const int bitflip,
                  word32 diffMC_list[DIFF_MC_MAX], int *len, int *col);

int r9_find_candidates(const byte ct[16], const byte fct[16],
                       const int fault_pos, const int fault,
                       const int bitflip, word32 candidates[CAND_MAX],
                       int *cand_len, int *col);

int r9_key_recovery(const byte pt[16], const byte ct[16],
                    const byte ct_list[][16], const byte fct_list[][16],
                    const int fault_pos_list[PAIRS_MAX],
                    const int fault_list[PAIRS_MAX], const int fct_len,
                    const int bitflip, byte masterkey[16]);



/* attack round 8 */

void r8_get_diffMC(const int col8, const word32 diff_col, const int col9,
                   word32 diffMC_list[DIFF_MC_MAX], int *len);

void r8_find_candidates(const byte ct[16], const byte fct[16],
                        const int row8, const int col8, const int fault,
                        word32 candidates[4][CAND_MAX], int cand_len[4]);

int r8_exhaustive_search(const byte pt0[16], const byte ct0[16],
                         const byte ct[16], const byte fct[16],
                         const int row8, const int col8, const int fault,
                         const word32 candidates[4][CAND_MAX],
                         const int cand_len[4], byte masterkey[16]);

int r8_key_recovery_single_ct(const byte pt0[16], const byte ct0[16],
                              const byte ct[16], const byte fct[16],
                              const int fault_pos, const int fault,
                              byte masterkey[16]);

int r8_key_recovery(const byte pt0[16], const byte ct0[16],
                    const byte ct_list[][16], const byte fct_list[][16],
                    const int fault_pos_list[PAIRS_MAX],
                    const int fault_list[PAIRS_MAX], const int fct_len,
                    byte masterkey[16]);

#endif
