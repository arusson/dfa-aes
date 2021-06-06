#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "dfa.h"

#define DFA_ROUND_8 8
#define DFA_ROUND_9 9

int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;

void print_instructions(const char *msg) {
  if (msg != NULL) {
    printf("Error: %s\n", msg);
  }
}


/**
 * c: single hex string
 */
byte char_to_nibble(const char c) {
  byte nib;
  if (c >= 48 && c <= 57) { nib = (byte)(c - 48); }
  else if (c >= 65 && c <= 70) { nib = (byte)(c - 55); }
  else if (c >= 97 && c <= 102) { nib = (byte)(c - 87); }
  else { nib = 255; }
  return nib;
}

void hex_to_bytes(const char *a, const int len, byte *b) {
  int i; 
  for (i = 0; i < len; i += 2) {
    b[i >> 1] = (char_to_nibble(a[i]) << 4) | char_to_nibble(a[i + 1]);
  }
}

int readfile(const char *filename, byte pt[16], byte ct[16],
             byte ct_list[][16], byte fct_list[][16], int *fault_pos_list,
             int *fault_list, int *len) {
  FILE *fp;
  char buffer[128];
  char *tmp;
  
  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  /* load plaintext and ciphertext from first line */
  fgets(buffer, 128, fp);
  hex_to_bytes(buffer, 32, pt);
  hex_to_bytes(buffer + 33, 32, ct);
  
  *len = 0;

  while (fgets(buffer, 128, fp)) {
    tmp = strtok(buffer, ",");
    hex_to_bytes(tmp, 32, ct_list[*len]);
    tmp = strtok(NULL, ",");
    hex_to_bytes(tmp, 32, fct_list[*len]);
    fault_pos_list[*len] = -1;
    fault_list[*len] = -1;
    tmp = strtok(NULL, ",");
    if (tmp != NULL) {
      fault_pos_list[*len] = atoi(tmp);
      tmp = strtok(NULL, ",");
      if (tmp != NULL) {
        fault_list[*len] = atoi(tmp);
      }
    }
    (*len)++;
    if (*len == PAIRS_MAX) {
      fprintf(stderr, "Warning: too many pairs of correct/faulty ciphertexts, "
             "some were discarded.\n");
      break;
    }
  }

  fclose(fp);
  return 0;
}


int main(int argc, char *argv[]) {
  
  byte pt[16], ct[16], masterkey[16];
  byte ct_list[PAIRS_MAX][16], fct_list[PAIRS_MAX][16];
  int fault_list[PAIRS_MAX], fault_pos_list[PAIRS_MAX];
  int i, len, opt, err, found;
  int mode = -1;
  int bitflip = 0;
  char options[] = "89bi:";
  char *filename = NULL;
  
  opt = getopt(argc, argv, options);
  while (opt != -1) {
    switch(opt) {
      
    case '8':
      if (mode == -1) {
        mode = DFA_ROUND_8;
      }
      else {
        print_instructions("-8 and -9 cannot be used at the same time");
        exit(EXIT_FAILURE);
      }
      break;
    case '9':
      if (mode == -1) {
        mode = DFA_ROUND_9;
      }
      else {
        print_instructions("-8 and -9 cannot be used at the same time");
        exit(EXIT_FAILURE);
      }
      break;
    case 'b':
      bitflip = 1;
      break;
    case 'i':
      filename = optarg;
      break;
      
    case '?':
      print_instructions("Options are missing");
      exit(EXIT_FAILURE);
      break;
    }
    opt = getopt(argc, argv, options);
  }
  
  if (mode == -1) {
    print_instructions("Option -8 or -9 missing");
    exit(EXIT_FAILURE);
  }
  
  if (filename == NULL) {
    print_instructions("Please provide an input file");
    exit(EXIT_FAILURE);
  }
  
  /* load data from file */
  err = readfile(filename, pt, ct, ct_list, fct_list,
                 fault_pos_list, fault_list, &len);
  if (err == -1) {
    print_instructions("Problem with the input file");
    exit(EXIT_FAILURE);
  }

  /* launch analysis */
  if (mode == DFA_ROUND_9) {
    found = r9_key_recovery(pt, ct, ct_list, fct_list, fault_pos_list,
                            fault_list, len, bitflip, masterkey);
  }
  else {
    if (len == 1) {
      found = r8_key_recovery_single_ct(pt, ct, ct_list[0], fct_list[0],
                                        fault_pos_list[0], fault_list[0],
                                        masterkey);
    }
    else {
      found = r8_key_recovery(pt, ct, ct_list, fct_list, fault_pos_list,
                              fault_list, len, masterkey);
    } 
  }
  
  /* print master key if found */
  if (found == 0) {
    printf("The attack was unsuccessful: check your data.\n");
  }
  else if (found == 1) {
    printf("The master key is ");
    for (i = 0; i < 16; i++) {
      printf("%02x", masterkey[i]);
    }
    printf("\n");
  }
  else {
    printf("Something is wrong somewhere.\n");
  }
  
  return 0;
}
  
  
