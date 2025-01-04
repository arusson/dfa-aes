# Differential Fault Analysis on AES

This program implements the DFA attack on AES-128 from pairs of correct and faulty ciphertexts.
Two cases are supported:

* Faults made on the 8th round;
* Faults made on the 9th round.

For each case, it is possible to specify the *fault location* and/or the *fault value*.

In the case of the fault in the **8th round**, this program is very **efficient** for key recovery with a **single fault**:
depending of the assumption on the fault, it can find the key immediately, or in less than a minute if nothing is known.

## Update 2025.01.04

A lot of changes has been made:
- use os **AES-NI** instructions to reduce drastically the cost (now, a few seconds can suffice to find a key with a single ciphertext pair for the 8th round fault);
- known plaintext/ciphertext is **optional**;
- a bitflip fault can be specified **without the fault position** (pretty useful with a single fault in round 8 as it reduces the number of key candidates to a handful);
- the input file format has been slightly changed (it can contain comments and indication of known plaintext/ciphertext is clearly separated from the declaration of ciphertext pairs).

The introduction of AES-NI instructions is based on the suggestion by [shuffle2](https://github.com/arusson/dfa-aes/issues/1).

## Overview

The differential fault analysis goal is to find the last AES round key (from which the master key can be reconstituted by reversing the key schedule).

It can be split in four chunks:
```
|x| | | |    | |x| | |    | | |x| |    | | | |x|
| | | |x|    |x| | | |    | |x| | |    | | |x| |
| | |x| |    | | | |x|    |x| | | |    | |x| | |
| |x| | |    | | |x| |    | | | |x|    |x| | | |
```
Each of those consists of four bytes in specific positions (it corresponds to a column after a *shift row* operation).
There are $2^{32}$ different values for each one, but the analysis reduces the number of candidates to $2^{10}$, $2^8$ or even less depending of what is known on the fault (16 candidates if fault position and value are known for the 9th round fault).

If necessary, other ciphertext pairs can be used to reduce further the candidates for each chunk of the last round key.

This part of the analysis is instantaneous.

In the case of the 8th round fault, a filtering is applied after this first analysis.
It consists of checking the consistency between a candidate for the last round key and the fault:
the decryption is applied up to the eight round for both good and faulty ciphertexts, and the difference (XOR) of the states is compared from what shoud be procuded by the fault (it must have a single non-null byte, then the position and value must agree on the assumption on the fault).

This reduces the number of candidates for the last round key without the knowledge of plaintext.
For example, if there are $2^8$ candidates for each chunk of the last round key, then there are ${(2^8)}^4=2^{32}$ candidates for the whole key.
After the filtering, we can expect around:
- around $2^{12}$ keys if nothing is known on the fault (*);
- around $2^8$ keys if the fault position is known;
- around $2^4$ keys if the fault position is known and its value is a bitflip;
- around 2 keys if the fault position and value are known.

This filtering needs to combine the four chunks of the last round key, so it goes through all combination.
Therefore, this is the more costly part (it contains AES-NI instructions for efficiency).

Of course, if a known plaintext/ciphertext is provided, a further check is made with an encryption, but only if those previous steps have been successfully completed.


> (*): actually, in this case the filtering is applied four times, with an hypothesis that the fault occurred in each column, so overall the filtering is applied on 16 billions keys (which is still very fast thanks to the improvement of this implementation).

## Install

Clone the repository and run the following command:

```bash
make
```

The OpenMP dependency can be deactivated by removing the flag `-fopenmp`, but this would have a significant impact on the performance.

The binary will be put in the `bin` folder.

## Usage

### Command line

For the 8th round attack, run the command:

```bash
./dfa -8 -i inputfile.txt
```

For the 9th round attack, run the command:

```bash
./dfa -9 -i inputfile.txt
```

If a known plaintext/ciphertext has been provided or a single AES master key has been found, then the key will be printed on *stdout*.

Otherwise, key candidates that have been found are collected in the file `keys.txt`.
This file can be customized with optional argument `-o`.

### Input file format

Data containing the ciphertext pairs (one valid, one obtained with a fault during encryption, both from the same plaintext) must be put into a text file.
Each ciphertext pair is put on a line like this (in hexadecimal):
```
<ciphertext>,<faultyciphertext>
```

Two optional values can be appended separated by a comma:

* Fault position:
  - an integer between 0 and 15 (according to the ordering of the AES specification of a block);
  - the integer -1 if the fault position is unknown and a fault value is specified;
  - empty if fault position is unknown and no fault value is specified.
* Fault value:
  - an integer between 1 and 255 for the difference made by the fault;
  - the letter `b` to specify that the fault is a bitflip;
  - empty if fault value is unknown.

Examples:
```
# no indication on the fault
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d

# fault occurred on position 6, fault value is unknown
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d,6

# fault occurred on position 6, fault is 32 (0x20)
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d,6,32

# fault occurred on position 6, fault is a bitflip
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d,6,b

# fault position is unknown, fault is a bitflip
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d,-1,b
```

If a couple plaintext/ciphertext is known, it must be indicated at anyplace in the file as follows:
```
pt:<plaintext>
ct:<ciphertext>
```

Comments can be added using `#` as first character of a line.

### Generate sample data

A Python script is provided to generate sample data.

To generate 4 pairs of correct/faulty ciphertexts with a random key and faults in round 9:

```bash
python3 faultsimulator.py -r 9 > sample.txt
```

Each faulty ciphertext is obtained with a fault on a different column (so it affects different bytes on the ciphertext).

The optional arguments are

* `-n N`: number of pairs of correct/faulty ciphertexts to generate multiplied by 4 (by default, `N=1`);
* `--keeppos`: keeps the position of the fault;
* `--keepfault`: keeps the fault value;
* `--bitflip`: faults are bitflips (it overrides `--keepfault`);
* `--keeppt`: keeps a known plaintext/ciphertext (commented by default).

To generate one pair of correct/faulty ciphertext with a random key and a fault in round 8:

```bash
python3 faultsimulator.py -r 8 > sample.txt
```

The optional arguments are the same except that `-n N` generates `N` pairs of correct/faulty ciphertexts.

The master key is kept as a comment.

## Examples

The following examples have been tested with an [Intel i5](https://www.intel.com/content/www/us/en/products/sku/226256/intel-core-i51250p-processor-12m-cache-up-to-4-40-ghz/specifications.html) that has 12 cores and 16 threads (up to 4.4 GHz).

### 8th round attack

#### Single ciphertext pair (known fault position and value)

Generate an example:
```bash
python3 faultsimulator.py -r 8 --keeppos --keepfault > round8_1pair_position_value.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_position_value.txt
```

With the file [examples/round8_1pair_position_value.txt](./examples/round8_1pair_position_value.txt), **one candidate key** is found **immediately** (or a few seconds on a single core):
```
[*] No known plaintext/ciphertext provided
[*] Number of threads: 16
[*] Processing a single ciphertext pair:
    - Pair: 350e6c0961a6cab97c19aff96e2ef395 b94fc5e1df1aa5b33346e596b2a0dbc0
    - Fault position: 15 (column 3)
    - Fault value: 0xb0
[*] Hypothesis: fault in column 3 and fault is '0xb0'
[*] Number of candidates for each position:
  |x| | | |    | |x| | |    | | |x| |    | | | |x|
  | | | |x|    |x| | | |    | |x| | |    | | |x| |
  | | |x| |    | | | |x|    |x| | | |    | |x| | |
  | |x| | |    | | |x| |    | | | |x|    |x| | | |
      96          112          128          128
[*] Number of master key candidates: 176160768 (< 2^28)
[*] Filtering (without plaintext validation)
[*] Number of keys after filtering: 1
[*] Potential master key found:
83bc414a8e27a0ea25665f8d268c2378
```

Since no known plaintext/ciphertext are used, it is indicated as a *potential* key.

#### Single ciphertext pair (known fault position, value is a bitflip)

Generate an example:
```bash
python3 faultsimulator.py -r 8 --keeppos --bitflip > round8_1pair_position_bitflip.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_position_bitflip.txt
```

With the file [examples/round8_1pair_position_bitflip.txt](./examples/round8_1pair_position_bitflip.txt), **8 candidate keys** are found in a **few seconds** (less than a minute on a single core).

This is the same as the previous case, but applied 8 times using one of the  8 possible bitflip values (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80).

#### Single ciphertext pair (known fault position, unknown value)

Generate an example:
```bash
python3 faultsimulator.py -r 8 --keeppos > round8_1pair_position_only.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_position_only.txt
```

With the file [examples/round8_1pair_position_only.txt](./examples/round8_1pair_position_only.txt), **231 candidate keys** are found in **10 seconds** (2.5 minutes on a single core):
```
[*] No known plaintext/ciphertext provided
[*] Number of threads: 16
[*] Processing a single ciphertext pair:
    - Pair: b21b5ad92ee9f3149823e6b18e2921d1 a0794d17b41a327a51cc5e7f9d69a307
    - Fault position: 12 (column 3)
    - Fault value: unknown
[*] Hypothesis: fault in column 3 and fault is unknown
[*] Number of candidates for each position:
  |x| | | |    | |x| | |    | | |x| |    | | | |x|
  | | | |x|    |x| | | |    | |x| | |    | | |x| |
  | | |x| |    | | | |x|    |x| | | |    | |x| | |
  | |x| | |    | | |x| |    | | | |x|    |x| | | |
     240          240          272          240
[*] Number of master key candidates: 3760128000 (< 2^32)
[*] Filtering (without plaintext validation)
[*] Number of keys after filtering: 231
[*] 231 keys written to file keys.txt
```

#### Single ciphertext pair (unknwon fault position, known value)

Generate an example:
```bash
python3 faultsimulator.py -r 8 --keepfault > round8_1pair_value_only.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_value_only.txt
```

This takes a longer time, since there are around $4\times 2^{32}$ candidates keys before filtering.

With the file [examples/round8_1pair_value_only.txt](./examples/round8_1pair_value_only.txt), **15 candidate keys** are found in **45 seconds** (more than 10 minutes on a single core).

#### Single ciphertext pair (unknown fault position, value is a bitflip)

Generate an example:
```bash
python3 faultsimulator.py -r 8 --bitflip > round8_1pair_bitflip_only.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_bitflip_only.txt
```

With the file [examples/round8_1pair_bitflip_only.txt](./examples/round8_1pair_bitflip_only.txt), **173 candidate keys** are found in **50 seconds** (more than 12 minutes on a single core).

Since the fault position is unknown, the knowledge that a fault is a bitlip is only used for the filtering.
So the running time shoud be similar to the previous case.

#### Single ciphertext pair (unknown fault position and value)

Generate an example:
```bash
python3 faultsimulator.py -r 8 > round8_1pair_unknown.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_1pair_unknown.txt
```

With the file [examples/round8_1pair_unknown.txt](./examples/round8_1pair_unknown.txt), **3774 candidate keys** are found in **46 seconds** (more than 11 minutes on a single core).

Again, the running time is similar to the previous two cases.

#### Multiple ciphertext pairs

Generate an example:
```bash
python3 faultsimulator.py -r 8 -n 2 > round8_2pairs.txt
```

Run the analysis:
```bash
./dfa -8 -i round8_2pairs.txt
```

With the file [examples/round8_2pairs.txt](./examples/round8_2pairs.txt), **one key** is found **immediately**:
```
[*] No known plaintext/ciphertext provided
[*] Number of threads: 16
[*] Number of candidates for each position:
  |x| | | |    | |x| | |    | | |x| |    | | | |x|
  | | | |x|    |x| | | |    | |x| | |    | | |x| |
  | | |x| |    | | | |x|    |x| | | |    | |x| | |
  | |x| | |    | | |x| |    | | | |x|    |x| | | |
       1            1            1            1
[*] Number of master key candidates: 1 (< 2^1)
[*] Potential master key found:
0714be497a6e020a4a5fe1d8ed312ae9
```

Since the analysis is run multiple times, then it is expected to find a single candidate for each chunk of the last round key.
In this case, it is completely unnecessary to have any assumption on the fault.

### 9th round attack

#### Two ciphertext pairs for each column

Generate an example:
```bash
python3 faultsimulator.py -r 9 -n 2 > round9_8pairs.txt
```

Run the analysis:
```bash
./dfa -9 -i round9_8pairs.txt
```

With the file [examples/round9_8pairs.txt](./examples/round9_8pairs.txt), **2 candidate keys** are found **immediately**.

Since there are two pairs for each column where a fault occurred in round 9, then there is one candidate (eventually two) for each chunk of the last round key.

#### Single ciphertext pair for each column (fault is bitflip)

Generate an example:
```bash
python3 faultsimulator.py -r 9 -n 1 --bitflip > round9_4pairs_bitflip_only.txt
```

Run the analysis:
```bash
./dfa -9 -i round9_4pairs_bitflip_only.txt
```

With the file [examples/round9_4pairs_bitflip_only.txt](./examples/round9_4pairs_bitflip_only.txt), **8388608 candidate keys** are found, but the program does not save them in a file:
```
[*] No known plaintext/ciphertext provided
[*] Number of threads: 16
[*] Processing ciphertext pair 1 out of 4:
    - Pair: b0a3fd31087ac9bcfabf540446605625 28a3fd31087ac9a0fabf980446a25625
    - Fault position: unknown
    - Fault value: bitflip
[*] 64 candidate(s) for positions 0, 13, 10, 7
[*] Processing ciphertext pair 2 out of 4:
    - Pair: 00d8d96ffedc4a934dd111d0cdb650cd 006bd96f8bdc4a934dd1119acdb604cd
    - Fault position: unknown
    - Fault value: bitflip
[*] 64 candidate(s) for positions 4, 1, 14, 11
[*] Processing ciphertext pair 3 out of 4:
    - Pair: 90facbeeef4f43bc3700a619868842ba 90fae4eeefbc43bc4400a619868842b1
    - Fault position: unknown
    - Fault value: bitflip
[*] 64 candidate(s) for positions 8, 5, 2, 15
[*] Processing ciphertext pair 4 out of 4:
    - Pair: c4279c7a2183ce923994d6d3c126adf3 c4279cd82183b59239cbd6d38626adf3
    - Fault position: unknown
    - Fault value: bitflip
[*] 32 candidate(s) for positions 12, 9, 6, 3
[*] Number of candidates for each position:
  |x| | | |    | |x| | |    | | |x| |    | | | |x|
  | | | |x|    |x| | | |    | |x| | |    | | |x| |
  | | |x| |    | | | |x|    |x| | | |    | |x| | |
  | |x| | |    | | |x| |    | | | |x|    |x| | | |
      64           64           64           32
[*] Number of master key candidates: 8388608 (< 2^24)
[!] Analysis aborted: too many candidates to save (maximum: 65536)
[!] Please provide a known plaintext or other ciphertext pairs
```

Contrary to the previous case, a single ciphertext pair is used to find candidates for each chunk of the last round key.
With the knowledge that faults are bitflips, the number of candidates is lower, but it might still be too large:
a limit is hardcoded in the program in the file [dfa.h](./include/dfa.h):
```c
#define KEYS_MAX 65536
```

In such case, other ciphertext pairs or a known plaintext/ciphertext can be added.
Another solution is to compile the program with a higher value (it is used to statically allocate a buffer to save keys).

## Licence

This work is released under the [MIT license](LICENSE).
