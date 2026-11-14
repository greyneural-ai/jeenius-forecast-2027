#!/usr/bin/env python3
"""Check revealed items against a sealed commitments file.

Each sealed item was committed as

    commitment = SHA-256(salt_hex + "\\n" + canonical(item))

where

* ``salt_hex`` is 32 random bytes written as 64 lowercase hex characters, one
  salt per item;
* ``canonical(item)`` is
  ``json.dumps(nfc(item), sort_keys=True, ensure_ascii=False, separators=(",", ":"))``
  encoded as UTF-8, with every string and every key normalised to Unicode NFC
  first. Items contain no floating-point numbers.

Usage:

    python3 verify.py commitments/2027-v1.txt reveal.json

``reveal.json`` holds one object, or a list of objects, of the form
``{"ordinal": 1, "salt": "<64 hex>", "item": {...}}``. The script prints the
file's SHA-256 fingerprint, then one line per object: ``OK``, ``MISMATCH``,
``UNKNOWN`` (no such ordinal in the file) or ``BAD`` (the object itself is
malformed). A ``MISMATCH`` or ``UNKNOWN`` line also names the line the item's
commitment is on, when it is in the file under another ordinal. A reveal file
with a repeated key in any object is refused. It exits 0 only when every
object is OK.

Standard library only; Python 3.8 or later.
"""

import hashlib
import json
import re
import sys
import unicodedata

_SALT = re.compile(r"[0-9a-f]{64}\Z")
_LINE = re.compile(r"(\d{6}) ([0-9a-f]{64})\Z")


def nfc(obj):
    """Return ``obj`` with every string, including dict keys, in Unicode NFC."""
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            key = nfc(key)
            if key in out:
                raise ValueError("two keys are the same after NFC normalisation: %r" % (key,))
            out[key] = nfc(value)
        return out
    if isinstance(obj, (list, tuple)):
        return [nfc(v) for v in obj]
    return obj


def _refuse_floats(obj):
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in a sealed item: %r" % (obj,))
    if isinstance(obj, dict):
        for value in obj.values():
            _refuse_floats(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _refuse_floats(value)


def canonical(item):
    """The exact bytes that are hashed for ``item``."""
    _refuse_floats(item)
    text = json.dumps(
        nfc(item), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )
    return text.encode("utf-8")


def commitment(item, salt_hex):
    """SHA-256(salt_hex + "\\n" + canonical(item)), as lowercase hex."""
    if not isinstance(salt_hex, str) or not _SALT.match(salt_hex):
        raise ValueError("salt must be 64 lowercase hex characters")
    digest = hashlib.sha256()
    digest.update((salt_hex + "\n").encode("ascii"))
    digest.update(canonical(item))
    return digest.hexdigest()


def read_commitments(text):
    """Parse a commitments file into ``(header, {ordinal: commitment})``."""
    header = {}
    lines = {}
    body = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not body:
            if line == "---":
                body = True
            elif not line.startswith("#"):
                key, sep, value = line.partition(":")
                if not sep:
                    raise ValueError("bad header line: %r" % (raw,))
                header[key.strip()] = value.strip()
            continue
        match = _LINE.match(line)
        if not match:
            raise ValueError("bad commitment line: %r" % (raw,))
        ordinal = int(match.group(1))
        if ordinal in lines:
            raise ValueError("ordinal %06d appears twice" % ordinal)
        lines[ordinal] = match.group(2)
    if not body:
        raise ValueError("no '---' line: not a commitments file")
    if "items" not in header or not header["items"].isdigit():
        raise ValueError("header has no item count")
    if int(header["items"]) != len(lines):
        raise ValueError(
            "header says %s items but the file has %d lines" % (header["items"], len(lines))
        )
    return header, lines


def file_fingerprint(path):
    """SHA-256 of the file's bytes, as lowercase hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key %r in the reveal file" % (key,))
        out[key] = value
    return out


def _check(record, lines, where):
    if not isinstance(record, dict):
        return "BAD ??????: not an object"
    ordinal = record.get("ordinal")
    if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
        return "BAD ??????: ordinal must be a whole number"
    label = "%06d" % ordinal
    item = record.get("item")
    if not isinstance(item, dict):
        return "BAD %s: item must be an object" % label
    try:
        computed = commitment(item, record.get("salt"))
    except ValueError as exc:
        return "BAD %s: %s" % (label, exc)
    if lines.get(ordinal) == computed:
        return "OK %s" % label
    verdict = ("MISMATCH %s" if ordinal in lines else "UNKNOWN %s") % label
    if computed in where:
        verdict += ": this item's commitment is on line %06d" % where[computed]
    return verdict


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: python3 verify.py <commitments.txt> <reveal.json>", file=sys.stderr)
        return 2
    commitments_path, reveal_path = argv
    try:
        with open(commitments_path, "rb") as fh:
            raw = fh.read()
        _, lines = read_commitments(raw.decode("utf-8"))
        with open(reveal_path, encoding="utf-8") as fh:
            reveal = json.load(fh, object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if b"\r" in raw:
        print("warning: this copy has CRLF line endings, so its fingerprint is not the published one;"
              " compare against the raw file from the repository", file=sys.stderr)
    records = reveal if isinstance(reveal, list) else [reveal]
    where = {value: ordinal for ordinal, value in lines.items()}
    print("fingerprint " + file_fingerprint(commitments_path))
    verdicts = [_check(record, lines, where) for record in records]
    for verdict in verdicts:
        print(verdict)
    return 0 if verdicts and all(v.startswith("OK ") for v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
