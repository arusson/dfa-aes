#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

/**
 * Convert a single hex character to a four-bit value.
 */
static uint8_t char_to_nibble(const char c) {
  uint8_t nib;
  if (c >= 48 && c <= 57) {
    nib = (uint8_t)(c - 48);
  }
  else if (c >= 65 && c <= 70) {
    nib = (uint8_t)(c - 55);
  }
  else if (c >= 97 && c <= 102) {
    nib = (uint8_t)(c - 87);
  }
  else {
    nib = 255;
  }
  return nib;
}

/**
 * This function goes through each character of the input string looking
 * for hexadecimal characters: each hex character forms a nibble (half byte)
 * that is added to the output buffer. Every non-hexadecimal characters is ignored.
 * An error occurs if the output buffer is not filled.
 * Extra characters are ignored.
 */
static int hex_to_bytes(const char *a, const int alen, uint8_t *b, const int blen) {
  int i = 0;
  int j = 0;
  int hi = 1;
  int ret = -1;
  uint8_t c;

  while (i < alen && j < blen) {
    /* get one hexadecimal character */
    c = char_to_nibble(a[i++]);
    if (c == 255) {
      continue;
    }

    /* add the four bits value to the output buffer */
    if (hi) {
      b[j] = c << 4;
      hi = 0;
    }
    else {
      b[j++] |= c;
      hi = 1;
    }
  }
  /* no error if the output is filled */
  if (j == blen && hi == 1) {
    ret = 0;
  }
  return ret;
}

/**
 * This function parses the input file.
 */
int readfile(const char *filename, pair_t pairs[PAIRS_MAX], int *npairs, known_pt_t *known_pt) {
  FILE *fp;
  int err = -1;
  int n;
  int num_line = 0;
  char buffer[128];
  char *tmp;
  bool has_pt = false;
  bool has_ct = false;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  /* read file line by line, order does not matter */
  while(fgets(buffer, 128, fp)) {
    num_line++;
    n = strlen(buffer);

    /* ignore commented lines with '#' or lines too short */
    if (n < 35 || buffer[0] == '#') {
      continue;
    }

    if (buffer[0] == 'p' && buffer[1] == 't' && buffer[2] == ':' && !has_pt) {
      /* load known plaintext */
      err = hex_to_bytes(buffer + 3, n - 3, known_pt->pt, 16);
      if (err != 0) {
        fprintf(stderr, "[!] Malformed input for known plaintext on line %d\n", num_line);
        exit(EXIT_FAILURE);
      }
      has_pt = true;
    }
    else if (buffer[0] == 'c' && buffer[1] == 't' && buffer[2] == ':' && !has_ct) {
      /* load ciphertext of known plaintext */
      err = hex_to_bytes(buffer + 3, n - 3, known_pt->ct, 16);
      if (err != 0) {
        fprintf(
          stderr,
          "[!] Malformed input for ciphertext of known plaintext on line %d\n", num_line
        );
        exit(EXIT_FAILURE);
      }
      has_ct = true;
    }
    else if (*npairs < PAIRS_MAX) {
      /* load first ciphertext from a pair of good/faulty ciphertexts */
      tmp = strtok(buffer, ",");
      err = hex_to_bytes(tmp, strlen(tmp), pairs[*npairs].ct, 16);
      if (err != 0) {
        fprintf(stderr, "[!] Malformed input for first ciphertext on line %d\n", num_line);
        exit(EXIT_FAILURE);
      }

      /* load second ciphertext from a pair of good/faulty ciphertexts */
      tmp = strtok(NULL, ",");
      err = hex_to_bytes(tmp, strlen(tmp), pairs[*npairs].fct, 16);
      if (err != 0) {
        fprintf(stderr, "[!] Malformed input for second ciphertext on line %d\n", num_line);
        exit(EXIT_FAILURE);
      }

      /* load fault position and fault value if present */
      tmp = strtok(NULL, ",");
      pairs[*npairs].bitflip = false;
      pairs[*npairs].fault_pos = -1;
      pairs[*npairs].fault_value = -1;
      if (tmp != NULL) {
        pairs[*npairs].fault_pos = atoi(tmp);
        if (pairs[*npairs].fault_pos < -1 || pairs[*npairs].fault_pos > 15) {
          fprintf(stderr, "[!] Malformed input for fault position on line %d\n", num_line);
          exit(EXIT_FAILURE);
        }
        tmp = strtok(NULL, " ");
        if (tmp != NULL) {
          if (tmp[0] == 'b') {
            pairs[*npairs].bitflip = true;
          }
          else {
            pairs[*npairs].fault_value = atoi(tmp);
            if (pairs[*npairs].fault_value < 1 || pairs[*npairs].fault_value > 255) {
              fprintf(stderr, "[!] Malformed input for fault value on line %d\n", num_line);
              exit(EXIT_FAILURE);
            }
          }
        }
      }

      (*npairs)++;
      if (*npairs == PAIRS_MAX) {
        fprintf(
          stderr,
          "[!] Maximum ciphertext pairs reached (%d), others will be discarded\n",
          PAIRS_MAX
        );
      }
    }
  }

  if (has_pt && !has_ct) {
    fprintf(stderr, "[!] Known plaintext ignored (corresponding ciphertext is absent)\n");
    known_pt->is_some = false;
  }
  else if (!has_pt && has_ct) {
    fprintf(stderr, "[!] Ciphertext ignored (corresponding known plaintext absent)\n");
    known_pt->is_some = false;
  }
  else {
    known_pt->is_some = has_pt;
    if (has_pt) {
      fprintf(stderr, "[*] Known plaintext/ciphertext provided\n");
    }
    else {
      fprintf(stderr, "[*] No known plaintext/ciphertext provided\n");
    }
  }

  fclose(fp);
  return 0;
}

void print_hex(const uint8_t *buffer, const int len) {
  int i;
  for (i = 0; i < len; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void print_pair_info(const pair_t *pair) {
  int i;
  fprintf(stderr, "    - Pair: ");
  for (i = 0; i < 16; i++) {
    fprintf(stderr, "%02x", pair->ct[i]);
  }
  fprintf(stderr, " ");
  for (i = 0; i < 16; i++) {
    fprintf(stderr, "%02x", pair->fct[i]);
  }
  if (pair->fault_pos != -1) {
    fprintf(
      stderr,
      "\n    - Fault position: %d (column %d)\n",
      pair->fault_pos, pair->fault_pos / 4
    );
  }
  else {
    fprintf(stderr, "\n    - Fault position: unknown\n");
  }
  if (pair->bitflip == true) {
    fprintf(stderr, "    - Fault value: bitflip\n");
  }
  else if (pair->fault_value != -1) {
    fprintf(stderr, "    - Fault value: 0x%02x\n", pair->fault_value);
  }
  else {
    fprintf(stderr, "    - Fault value: unknown\n");
  }
}

void print_number_candidates_line(const int num, const int col) {
  if (col == 0) {
    fprintf(stderr, "[*] %d candidate(s) for positions 0, 13, 10, 7\n", num);
  }
  else if (col == 1) {
    fprintf(stderr, "[*] %d candidate(s) for positions 4, 1, 14, 11\n", num);
  }
  else if (col == 2) {
    fprintf(stderr, "[*] %d candidate(s) for positions 8, 5, 2, 15\n", num);
  }
  else {
    fprintf(stderr, "[*] %d candidate(s) for positions 12, 9, 6, 3\n", num);
  }
}

static int bit_length(const long a) {
    return 64 - __builtin_clzl((unsigned long)a);
}

void print_number_candidates(const int candidates_len[4], const long nb_cand) {
  fprintf(
    stderr,
    "[*] Number of candidates for each position:\n"
    "  |x| | | |    | |x| | |    | | |x| |    | | | |x|\n"
    "  | | | |x|    |x| | | |    | |x| | |    | | |x| |\n"
    "  | | |x| |    | | | |x|    |x| | | |    | |x| | |\n"
    "  | |x| | |    | | |x| |    | | | |x|    |x| | | |\n"
    "    %4d         %4d         %4d         %4d\n"
    "[*] Number of master key candidates: %ld (< 2^%d)\n",
    candidates_len[0], candidates_len[1], candidates_len[2], candidates_len[3],
    nb_cand, bit_length(nb_cand)
  );
}
