"""Tests for verify.py. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import verify  # noqa: E402

SALT = "00" * 32
ITEM = {"kind": "question", "question_id": 1, "question": "θ = 30°, find é"}


def _sample(items_line="items: 2", lines=None):
    if lines is None:
        lines = ["000001 " + "a" * 64, "000002 " + "b" * 64]
    return "\n".join([
        "# Jeenius JEE Main 2027 forecast: sealed commitments",
        "format: 1",
        "version: 2027-v1",
        "freeze_utc: 2026-11-15T00:00:00Z",
        items_line,
        'hash: sha256(salt_hex + "\\n" + canonical(item))',
        "backend_commit: " + "c" * 40,
        "---",
        *lines,
    ]) + "\n"


SAMPLE = _sample()


class CanonicalTest(unittest.TestCase):
    def test_canonical_sorts_keys_and_has_no_spaces(self):
        self.assertEqual(verify.canonical({"b": 1, "a": "x"}), b'{"a":"x","b":1}')

    def test_canonical_keeps_unicode_raw(self):
        self.assertEqual(verify.canonical({"q": "θ = 30°"}), '{"q":"θ = 30°"}'.encode("utf-8"))

    def test_nfd_and_nfc_give_same_bytes(self):
        self.assertEqual(verify.canonical({"q": "é"}), verify.canonical({"q": "é"}))

    def test_nfc_applies_to_keys_and_nested_lists(self):
        self.assertEqual(
            verify.canonical({"é": [{"t": "é"}]}),
            verify.canonical({"é": [{"t": "é"}]}),
        )

    def test_float_is_refused(self):
        with self.assertRaises(ValueError):
            verify.canonical({"w": 0.5})
        with self.assertRaises(ValueError):
            verify.canonical({"w": [1, {"x": float("nan")}]})
        self.assertEqual(verify.canonical({"c": True, "n": None}), b'{"c":true,"n":null}')


class CommitmentTest(unittest.TestCase):
    def test_commitment_known_vector(self):
        expected = hashlib.sha256(
            (SALT + "\n").encode("ascii") + b'{"kind":"question","question_id":1}'
        ).hexdigest()
        self.assertEqual(verify.commitment({"kind": "question", "question_id": 1}, SALT), expected)

    def test_bad_salt_refused(self):
        for salt in ("AB" * 32, "00" * 31, "zz" * 32, 123):
            with self.assertRaises(ValueError):
                verify.commitment({"a": 1}, salt)


class ReadCommitmentsTest(unittest.TestCase):
    def test_read_commitments_parses_header_and_lines(self):
        header, lines = verify.read_commitments(SAMPLE)
        self.assertEqual(header["items"], "2")
        self.assertEqual(header["version"], "2027-v1")
        self.assertEqual(sorted(lines), [1, 2])
        self.assertEqual(lines[1], "a" * 64)

    def test_read_commitments_rejects_count_mismatch(self):
        with self.assertRaises(ValueError):
            verify.read_commitments(SAMPLE.replace("items: 2", "items: 3"))

    def test_read_commitments_rejects_repeated_ordinal(self):
        text = _sample(lines=["000001 " + "a" * 64, "000001 " + "b" * 64])
        with self.assertRaises(ValueError):
            verify.read_commitments(text)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        good = verify.commitment(ITEM, SALT)
        self.commitments = os.path.join(self.tmp.name, "c.txt")
        with open(self.commitments, "w", encoding="utf-8") as fh:
            fh.write(_sample(lines=["000001 " + good, "000002 " + "b" * 64]))

    def run_cli(self, reveal, indent=None):
        path = os.path.join(self.tmp.name, "reveal.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(reveal, fh, ensure_ascii=False, indent=indent)
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "verify.py"), self.commitments, path],
            capture_output=True, text=True,
        )

    def test_cli_ok_and_mismatch(self):
        ok = self.run_cli({"ordinal": 1, "salt": SALT, "item": ITEM})
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("OK 000001", ok.stdout)
        self.assertTrue(ok.stdout.startswith("fingerprint " + verify.file_fingerprint(self.commitments)))
        tampered = dict(ITEM, question="θ = 31°, find é")
        bad = self.run_cli([{"ordinal": 1, "salt": SALT, "item": tampered}])
        self.assertEqual(bad.returncode, 1)
        self.assertIn("MISMATCH 000001", bad.stdout)

    def test_cli_pretty_printed_reveal_still_matches(self):
        reordered = dict(reversed(list(ITEM.items())))
        res = self.run_cli({"item": reordered, "salt": SALT, "ordinal": 1}, indent=2)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("OK 000001", res.stdout)

    def test_cli_unknown_ordinal(self):
        res = self.run_cli({"ordinal": 99, "salt": SALT, "item": ITEM})
        self.assertEqual(res.returncode, 1)
        self.assertIn("UNKNOWN 000099", res.stdout)
        self.assertNotIn("Traceback", res.stderr)

    def test_cli_bad_salt_is_reported_not_raised(self):
        res = self.run_cli({"ordinal": 1, "salt": SALT.upper().replace("0", "A"), "item": ITEM})
        self.assertEqual(res.returncode, 1)
        self.assertTrue(any(l.startswith("BAD 000001:") for l in res.stdout.splitlines()), res.stdout)
        self.assertNotIn("Traceback", res.stderr)


if __name__ == "__main__":
    unittest.main()
