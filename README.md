# Differential Fault Analysis on AES

This program implements the DFA attack on AES-128 in the situations where pair of correct and faulty ciphertexts are known.
Two cases are supported:

* Faults made on the 9th round;
* Faults made on the 8th round.

For each case, it is possible to specify the *fault location* and/or the *fault value*.

## Install

Clone the repository and run the command

```bash
make
```

The OpenMP dependency can be deactivated by removing the flag `-fopenmp`, but this would have a significant impact on the performance.

The binary will be put in the `bin` folder.

## Usage

The input files must be text files must start with a line

```
<plaintext0>,<ciphertext0>
```

and followed by one or several lines

```
<ciphertext1>,<faultyciphertext1>
```

Two optional values can be appended:

* an integer between 0 and 15 to indicate the position of the fault
* an integer between 1 and 255 to indicate the fault value (difference made by the fault)

Example:

```
e9aa4848b46a1a451c2d1417d61910a1,e8b76b446765462e890a1d29de50762a
7c1d31deae92594a2820ec01de33c897,488f7b0b41b352cef70d491067f8d87d,6,32
```

The first line is the plaintext and its corresponding ciphertext, while the second line is a correct and its faulty version where a fault was made on position 7 and 32 as the difference (as 32 is a power of 2, it is a bitflip).

For the round 9 attack, run the command

```bash
./dfa -9 -i sample.txt
```

For the round 8 attack, run the command

```bash
./dfa -8 -i sample.txt
```

There is an optional argument `-b` for the round 9 attack. It indicates that the faults are known to be bitflips. In the case fault values are given in the input data, those are override with `-b`.

## Generate Sample Data

A Python script is provided to generate sample data.

To generate 4 pairs of correct/faulty ciphertexts with a random key and faults in round 9:

```bash
python3 faultsimulator.py -r 9 > sample.txt
```

Each faulty ciphertext was obtained with a fault on a different column.

The optional arguments are

* `-n <N>`: number of pairs of correct/faulty ciphertexts to generate multiplied by 4 (by default, `N=1`)
* `--keeppos`: keeps the position of the fault
* `--keepfault`: keeps the fault value (his option also keeps the position)
* `--bitflip`: faults are bitflips.

To generate one pair of correct/faulty ciphertext with a random key and a fault in round 8:

```bash
python3 faultsimulator.py -r 8 > sample.txt
```

The optional arguments are the same except that `-n <N>` generates `N` pairs of correct/faulty ciphertexts.

## Examples

### Round 9

##### Example 1

```bash
python3 faultsimulator.py -r 9 -n 2 > round9_8pairs.txt
```

The file `round9_8pairs.txt` contains 8 pairs of correct/faulty ciphertexts (two fault for each column in round 9). The fault positions and values are **unknown**. Then we run the command:

```bash
./dfa -9 -i round9_8pairs.txt
```

The master key is found immediately.

##### Example 2

```bash
python3 faultsimulator.py -r 9 --bitflip > round9_bitflip.txt
```

The file `round9_bitflip.txt` contains 4 pairs of correct/faulty ciphertexts (one for each column in round 9), where fault are known to be **bitflips** (but the exact fault and locations are unknowns). We run the command:

```bash
./dfa -9 -b -i round9_bitflip.txt
```

The analysis is a bit longer but should work in a few seconds.

### Round 8

##### Example 3

```bash
python3 faultsimulator.py -r 8 -n 2 > round8_2pairs.txt
```

The file `round8_2pairs.txt` contains two pairs of correct/faulty ciphertexts with **unknown** faults in round 8. We run the command

```bash
./dfa -8 -i round8_2pairs.txt
```

The master key is found immediately.

##### Example 4

```bash
python3 faultsimulator.py -r 8 --keeppos > round8_keeppos.txt
```

The file `round8_keeppos.txt` contains a single pair of correct/faulty ciphertexts. The **position is known** but the **fault is unknown**.

Run the command

```bash
./dfa -8 -i round8_keeppos.txt
```

Depending of the number of cores available and performance of the machine, it can take up to a few minutes as we expect around 4 billions keys to test.

*Remark*: if the fault location is unknown, it is expected to have around 16 billions keys to test, as the code will try to guess which column the fault was made, thus a factor by 4.

##### Example 5

```bash
python3 faultsimulator.py -r 8 --keepfault > round8_keepfault.txt
```

The file `round8_keepfault.txt` contains a single pair of correct/faulty ciphertexts. The position and fault are *known*.

Run the command

```bash
./dfa -8 -i round8_keepfault.txt
```

A speed-up of a factor of 16 can be expected compared to example 4 above (a few hundred millions candidates only).

The master key should be found in a few seconds.

## Future update

Currently, a pair plaintext/ciphertext must be provided to run the exhaustive search and valide the correct key.
Though, in some situations the number of candidates is low enough that it could be sufficient to output them directly
without requiring a plaintext.

Therefore, a future update will add the possibility to run the attack only from couple(s) of correct/faulty ciphertexts
and to print the master key candidates (if their number is not too large).
