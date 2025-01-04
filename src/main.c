#include <stdio.h>
#include <stdlib.h>
#include "dfa.h"
#ifdef _OPENMP
#include "omp.h"
#endif

static char *DEFAULT_OUTPUT_FILENAME = "keys.txt";

int main(int argc, char *argv[]) {
  FILE *fp = NULL;
  pair_t pairs[PAIRS_MAX];
  known_pt_t known_pt;
  int i, j, opt, err, nkeys, npairs;
  int mode = -1;
  uint8_t masterkeys[KEYS_MAX][16];
  char options[] = "89o:i:";
  char *in_fname = NULL;
  char *out_fname = NULL;
#ifdef _OPENMP
  int num_threads;
#endif

  /* scan command line arguments */
  opt = getopt(argc, argv, options);
  while (opt != -1) {
    switch(opt) {

    case '8':
      if (mode == -1) {
        mode = DFA_ROUND_8;
      }
      else {
        fprintf(stderr, "[!] -8 and -9 cannot be used at the same time\n");
        exit(EXIT_FAILURE);
      }
      break;

    case '9':
      if (mode == -1) {
        mode = DFA_ROUND_9;
      }
      else {
        fprintf(stderr, "[!] -8 and -9 cannot be used at the same time\n");
        exit(EXIT_FAILURE);
      }
      break;

    case 'i':
      in_fname = optarg;
      break;

    case 'o':
      out_fname = optarg;
      break;

    case '?':
      fprintf(stderr, "[!] Options are missing\n");
      exit(EXIT_FAILURE);
      break;
    }
    opt = getopt(argc, argv, options);
  }

  if (mode == -1) {
    fprintf(stderr, "[!] Option -8 or -9 missing\n");
    exit(EXIT_FAILURE);
  }

  if (in_fname == NULL) {
    fprintf(stderr, "[!] Please provide an input file\n");
    exit(EXIT_FAILURE);
  }

  if (out_fname == NULL) {
    out_fname = DEFAULT_OUTPUT_FILENAME;
  }

  /* load data from file */
  err = readfile(in_fname, pairs, &npairs, &known_pt);
  if (err == -1) {
    fprintf(stderr, "[!] Input file cannot be opened\n");
    exit(EXIT_FAILURE);
  }

  if (known_pt.is_some) {
    fprintf(stderr, "[*] A known plaintext/ciphertext has been provided\n");
  }

#ifdef _OPENMP
  num_threads = omp_get_max_threads();
  fprintf(stderr, "[*] Number of threads: %d\n", num_threads);
#endif

  /* launch analysis */
  if (mode == DFA_ROUND_9) {
    nkeys = r9_key_recovery(pairs, npairs, &known_pt, masterkeys);
  }
  else {
    nkeys = r8_key_recovery(pairs, npairs, &known_pt, masterkeys);
  }

  if (nkeys == 0) {
    fprintf(stderr, "[*] The attack was unsuccessful: check your data\n");
  }
  else {
    if (nkeys == 1) {
      if (known_pt.is_some) {
        fprintf(stderr, "[*] Master key found:\n");
      }
      else {
        fprintf(stderr, "[*] Potential master key found:\n");
      }
      print_hex(masterkeys[0], 16);
    }
    else {
      /* write all keys to file */
      fp = fopen(out_fname, "w");
      if (fp == NULL) {
        fprintf(stderr, "[!] Cannot write to file '%s', writing to '/tmp/keys.txt'\n", out_fname);
        out_fname = "/tmp/keys.txt";
        fp = fopen(out_fname, "w");
        if (fp == NULL) {
          fprintf(stderr, "[!] Cannot write to file '/tmp/keys.txt', I give up\n");
          exit(EXIT_FAILURE);
        }
      }
      for (i = 0; i < nkeys; i++) {
        for (j = 0; j < 16; j++) {
          fprintf(fp, "%02x", masterkeys[i][j]);
        }
        fprintf(fp, "\n");
      }
      fprintf(stderr, "[*] %d keys written to file %s\n", nkeys, out_fname);
      fclose(fp);
    }
  }

  return 0;
}
