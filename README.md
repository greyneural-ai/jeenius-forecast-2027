# Jeenius JEE Main 2027 forecast: sealed commitments

This repository holds a sealed record of a forecast made by Jeenius JEE for the
JEE Main 2027 exam. Each sealed item is published only as a fingerprint
(a salted SHA-256 hash). The items themselves are not in this repository.

## What was sealed

`commitments/2027-v1.txt` holds one commitment per item, 2222 in all:

| Kind | Items |
|---|---|
| Practice questions (text, options, answer and labels) | 2219 |
| The forecast of how the paper's questions spread across topics, difficulty and type | 1 |
| The topic plan the questions were written against | 1 |
| The fingerprint of the practice book as a file | 1 |

The order of the lines was shuffled, so a line's number says nothing about what
it holds.

## When

The file records `freeze_utc: 2026-11-14T20:23:44Z`. That is the time the
commitments were made, as written by the tool that made them.

The file itself is timestamped with [OpenTimestamps](https://opentimestamps.org),
which anchors its hash in the Bitcoin blockchain. The proof is
`commitments/2027-v1.txt.ots`. It proves the file existed no later than the
block it is anchored in.

## Fingerprint of the file

```
sha256(commitments/2027-v1.txt) = 458e0cf6d88ee85f596ea3bced834e2f7ee15ae6695ddccc78d41a63f0352962
```

Check it with `shasum -a 256 commitments/2027-v1.txt` (macOS) or
`sha256sum commitments/2027-v1.txt` (Linux).

## How each commitment was made

```
commitment = SHA-256(salt_hex + "\n" + canonical(item))
```

- `salt_hex` is 32 random bytes written as 64 lowercase hex characters. Every
  item has its own salt, so one item's commitment says nothing about another's,
  and an item cannot be guessed from its hash.
- `canonical(item)` is
  `json.dumps(nfc(item), sort_keys=True, ensure_ascii=False, separators=(",", ":"))`
  encoded as UTF-8, with every string and key normalised to Unicode NFC first.
  Items contain no floating-point numbers.

`verify.py` holds the exact code. It needs Python 3.8 or later and nothing
outside the standard library.

## How to check a revealed item

Anyone holding an item, its salt and its line number can check it against this
file. Put them in a JSON file, one object or a list of objects:

```json
{"ordinal": 1, "salt": "<64 hex characters>", "item": {"kind": "...", "...": "..."}}
```

Then run:

```
python3 verify.py commitments/2027-v1.txt reveal.json
```

It prints the file's fingerprint, then one line per object: `OK`, `MISMATCH`,
`UNKNOWN` (no such line number in the file) or `BAD` (the object itself is
malformed). It exits 0 only when every object is `OK`. Key order and spacing
in `reveal.json` do not matter.

## How to check the timestamp

With the OpenTimestamps client (`pip install opentimestamps-client`):

```
ots verify commitments/2027-v1.txt.ots
```

Or drop both files on [opentimestamps.org](https://opentimestamps.org).

A freshly made proof is pending until the calendars include it in a Bitcoin
block, which takes a few hours. Until it is upgraded here, `ots verify` reports
it as pending.

## This file does not change

`commitments/2027-v1.txt` is never edited or replaced. Anything sealed later
goes in a new file with a new version number.

## Tests

```
python3 -m unittest discover -s tests -v
```
