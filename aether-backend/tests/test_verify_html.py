"""Phase 7 — independent browser chain verifier.

The important property here is that verify.html reproduces the *same* canonical
bytes the backend signs and hashes. A verifier that computes a different
canonical form is worse than no verifier at all, because it reports a clean
chain for a tampered file. These tests extract the JavaScript out of verify.html
and execute it under Node, then compare its output against
``app.services.custody`` directly.
"""

import csv
import io
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.custody import GENESIS_HASH, CustodyChain, _canonical, canonical_bytes

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
VERIFY_HTML = REPO_ROOT / "verify.html"
FRONTEND_COPY = REPO_ROOT / "aether-frontend" / "public" / "verify.html"

REQUIRED_COLUMNS = [
    "seq", "timestamp_utc", "operator", "action", "payload", "prev_hash", "hash", "signature", "key_id",
]

NODE = shutil.which("node") or shutil.which("nodejs")
requires_node = pytest.mark.skipif(NODE is None, reason="Node is unavailable; JS parity tests skipped.")


def unescape_in_python(value: str) -> str:
    """Mirror of the JS unescapeCell, for asserting the rule without Node."""
    return value[1:] if len(value) > 1 and value[0] == "'" else value


# --------------------------------------------------------------------------- #
# The page itself
# --------------------------------------------------------------------------- #

def test_verify_html_exists_at_repo_root():
    assert VERIFY_HTML.is_file()
    assert VERIFY_HTML.stat().st_size > 5000


def test_verify_html_uses_web_crypto_not_a_third_party_library():
    html = VERIFY_HTML.read_text(encoding="utf-8")
    assert "crypto.subtle.digest" in html
    assert "crypto.subtle" in html
    # No external scripts, no CDN, no network calls: the page must work on an
    # air-gapped machine in front of a magistrate.
    assert "<script src=" not in html
    assert "http://" not in html.replace("http://www.w3.org", "")
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_verify_html_documents_the_statutory_basis():
    html = VERIFY_HTML.read_text(encoding="utf-8")
    assert "Section 63, Bharatiya Sakshya Adhiniyam, 2023" in html
    assert "s.65B, Indian Evidence Act, 1872" in html


def test_verify_html_uses_the_existing_design_system():
    """The verifier must be the same instrument as the console it accompanies.

    The theme is the console's: cold near-black surfaces from the seven-step
    ramp, hairline borders, the four ink roles, the four semantic state colours,
    and 0px radius. These are the exact values from
    aether-frontend/src/app/globals.css @theme, asserted individually so a
    partial revert cannot pass.

    This test previously asserted "#0f172a" and "#000000", which pinned the
    verifier to a light-mode palette the console no longer uses.
    """
    html = VERIFY_HTML.read_text(encoding="utf-8")

    # House identity: nothing is rounded.
    assert "border-radius: 0 !important" in html

    # Surface ramp, canvas first. #000000 is absent on purpose: the console
    # argues against it explicitly (OLED halation) in globals.css.
    for token in (
        "--canvas: #08090c",
        "--sunken: #06080d",
        "--input: #080b10",
        "--card: #0d1017",
        "--surface: #12161f",
        "--raised: #1a2230",
        "--active: #1e2736",
    ):
        assert token in html, f"missing console surface token {token!r}"
    assert "#000000" not in html, "the console does not use pure black; see globals.css"

    # Four hairline weights and four ink roles.
    for token in (
        "--line-faint: #141c29",
        "--line: #1e2533",
        "--line-strong: #273447",
        "--line-active: #37455d",
        "--ink: #f1f5f9",
        "--ink-muted: #94a3b8",
        "--ink-dim: #8593a8",
        "--ink-faint: #8292a8",
    ):
        assert token in html, f"missing console ink/line token {token!r}"

    # Every semantic state the verdict banners rely on.
    for token in (
        "--signal: #22c55e",
        "--signal-surface: #0f2419",
        "--alert: #dc2626",
        "--alert-surface: #2a1215",
        "--warn: #f59e0b",
        "--warn-surface: #251e10",
        "--info: #38bdf8",
        "--info-surface: #121a26",
        "--focus: #7dd3fc",
    ):
        assert token in html, f"missing console semantic token {token!r}"

    assert "--font-mono" in html
    assert "outline: 2px solid var(--focus)" in html, "one focus ring, as in the console"


def test_verify_html_ink_roles_clear_wcag_aa_on_the_card_surface():
    """The console asserts 4.5:1 for its ink roles on --color-card. Verify it.

    The previous theme pinned --ink-faint at 5.13:1 against a light card, which
    is what made the light palette pass. On this near-black ramp the same role
    has to be measured again rather than assumed, and it is measured here
    against the real values rather than against a comment.
    """
    html = VERIFY_HTML.read_text(encoding="utf-8")

    def channel(value: str) -> float:
        v = value / 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    def luminance(colour: str) -> float:
        r, g, b = (int(colour[i : i + 2], 16) for i in (1, 3, 5))
        return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)

    def ratio(fg: str, bg: str) -> float:
        a, b = luminance(fg), luminance(bg)
        return (max(a, b) + 0.05) / (min(a, b) + 0.05)

    card = "#0d1017"
    for role in ("#f1f5f9", "#94a3b8", "#8593a8", "#8292a8"):
        assert role in html, f"missing ink role {role}"
        assert ratio(role, card) >= 4.5, f"{role} is below 4.5:1 on {card}"


def test_verify_html_is_copied_into_the_frontend_public_dir():
    assert FRONTEND_COPY.is_file(), "verify.html must be served from the Next.js public dir"
    assert "crypto.subtle.digest" in FRONTEND_COPY.read_text(encoding="utf-8")


def test_the_two_verify_html_copies_are_byte_identical():
    """The repo root and the Next.js public dir hold two copies of one file.

    The root copy is the canonical one that the parity tests below extract and
    execute, and the public copy is what the console actually serves. Nothing
    generated the second one, so nothing kept them in step: the previous test
    only asserted the served copy existed and contained one string, which stays
    true no matter how far the two drift.

    That failure mode is not cosmetic. An exported statutory certificate tells a
    verifier to open "the zero-dependency browser verification utility", and the
    console links to the served copy. If those are different files, a third
    party runs a different verifier from the one this test suite validated — the
    exact outcome the offline verifier exists to prevent.

    Edit the root copy, then copy it across:
        copy verify.html aether-frontend\\public\\verify.html   # Windows
        cp verify.html aether-frontend/public/verify.html       # POSIX
    """
    canonical = VERIFY_HTML.read_bytes()
    served = FRONTEND_COPY.read_bytes()
    if canonical != served:
        differing = [
            i
            for i, (a, b) in enumerate(zip(canonical, served))
            if a != b
        ]
        first = differing[0] if differing else min(len(canonical), len(served))
        raise AssertionError(
            "verify.html has drifted between the repo root and the served copy. "
            f"root={len(canonical)}B public={len(served)}B, "
            f"{len(differing)} byte(s) differ, first at offset {first}."
        )


def test_verify_html_feature_detects_ed25519():
    html = VERIFY_HTML.read_text(encoding="utf-8")
    assert "Ed25519" in html
    assert "ed25519Available" in html
    assert "unsupported" in html


# --------------------------------------------------------------------------- #
# CSV export contract
# --------------------------------------------------------------------------- #

def test_custody_csv_header_contains_every_canonical_field():
    chain = CustodyChain()
    chain.append("Investigator", "Entry one")
    chain.append("Investigator", "Entry two")
    rows = []
    for entry in chain.entries:
        rows.append({
            "seq": entry.seq, "timestamp": entry.timestamp, "actor": entry.actor,
            "action": entry.action, "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash, "signature": entry.signature, "key_id": entry.key_id,
        })

    from app.services.export import build_custody_csv

    out = build_custody_csv(rows)
    parsed = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    assert parsed[0] == REQUIRED_COLUMNS
    assert len(parsed) == 3
    for row in parsed[1:]:
        assert len(row) == len(REQUIRED_COLUMNS)


# --------------------------------------------------------------------------- #
# JavaScript / Python canonical-form parity
# --------------------------------------------------------------------------- #

def _extract_js_functions() -> str:
    """Slice the self-contained logic out of verify.html.

    Starts at the constants (GENESIS_HASH, REQUIRED_COLUMNS) and stops before
    the DOM wiring section, which would throw on a null document under Node.
    Everything in between - canonicalization, CSV parsing, and chain
    verification - is executed unmodified, so these tests exercise the code the
    browser actually runs rather than a re-implementation of it.
    """
    html = VERIFY_HTML.read_text(encoding="utf-8")
    start = html.index("var GENESIS_HASH")
    end = html.index("/* ---------------- Wiring")
    return html[start:end]


HARNESS = r"""
/*__FUNCTIONS__*/

const fs = require("fs");
const nodeCrypto = require("crypto");
globalThis.crypto = {
  subtle: {
    digest: async (algo, data) => {
      const hash = nodeCrypto.createHash("sha256");
      hash.update(Buffer.from(data));
      return hash.digest().buffer;
    },
  },
};

const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = [];
for (const c of cases) {
  out.push(canonicalEntry({
    seq: c.seq,
    timestamp_utc: c.timestamp,
    operator: c.operator,
    action: c.action,
    prev_hash: c.prev_hash,
    hash: c.hash,
  }));
  out.push(canonicalSignature({
    seq: c.seq,
    timestamp_utc: c.timestamp,
    operator: c.operator,
    action: c.action,
    prev_hash: c.prev_hash,
    hash: c.hash,
  }));
}
process.stdout.write(JSON.stringify(out));
"""


def _run_node(template: str, payload: str, tmp_path: Path) -> str:
    """Execute a verify.html harness under Node with a payload on disk.

    The payload goes through a file rather than argv so that embedded newlines,
    BOMs, and non-ASCII characters survive intact on every platform.
    """
    script = template.replace("/*__FUNCTIONS__*/", _extract_js_functions())
    script_path = tmp_path / "harness.js"
    payload_path = tmp_path / "payload.txt"
    script_path.write_text(script, encoding="utf-8")
    # newline="" is essential: the default text mode would translate every "\n"
    # into "\r\n" on Windows and silently corrupt the CSV under test.
    with payload_path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(payload)

    completed = subprocess.run(
        [NODE, str(script_path), str(payload_path)],
        capture_output=True, timeout=180, cwd=str(BACKEND_ROOT),
    )
    stdout = completed.stdout.decode("utf-8")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    assert completed.returncode == 0, stderr
    return stdout


def _build_harness(template: str) -> str:
    return template.replace("/*__FUNCTIONS__*/", _extract_js_functions())


def _run_js(cases: list[dict], tmp_path: Path) -> list[str]:
    return json.loads(_run_node(HARNESS, json.dumps(cases), tmp_path))


# Deliberately hostile inputs: quotes, backslashes, control characters, astral
# emoji, and Devanagari. These are exactly the cases where a naive
# implementation of either language diverges.
PARITY_CASES = [
    {"seq": 1, "timestamp": "2026-09-27T04:11:07Z", "operator": "AETHER Pipeline", "action": "Investigation initiated", "prev_hash": GENESIS_HASH, "hash": "a" * 64},
    {"seq": 2, "timestamp": "2026-09-27T04:14:11Z", "operator": "Lead Forensics Officer", "action": 'He said "ship it" \\ now', "prev_hash": "a" * 64, "hash": "b" * 64},
    {"seq": 3, "timestamp": "2026-09-27T04:17:11Z", "operator": "गवाह", "action": "नमस्ते दुनिया", "prev_hash": "b" * 64, "hash": "c" * 64},
    {"seq": 4, "timestamp": "2026-09-27T04:20:11Z", "operator": "OPS", "action": "tab\there\nnewline\rcr\x07bell", "prev_hash": "c" * 64, "hash": "d" * 64},
    {"seq": 5, "timestamp": "2026-09-27T04:23:11Z", "operator": "OPS", "action": "emoji 🚀 and 🇮🇳 flag", "prev_hash": "d" * 64, "hash": "e" * 64},
    {"seq": 6, "timestamp": "2026-09-27T04:26:11Z", "operator": "", "action": "", "prev_hash": GENESIS_HASH, "hash": ""},
    {"seq": 7, "timestamp": "2026-09-27T04:29:11Z", "operator": "=cmd|calc", "action": "@SUM(A1)", "prev_hash": "f" * 64, "hash": "0" * 64},
]


@requires_node
def test_js_canonical_form_matches_python_byte_for_byte(tmp_path):
    js_output = _run_js(PARITY_CASES, tmp_path)
    expected = []
    for case in PARITY_CASES:
        expected.append(json.dumps(
            {
                "seq": case["seq"],
                "timestamp": case["timestamp"],
                "actor": case["operator"],
                "action": case["action"],
                "prev_hash": case["prev_hash"],
            },
            sort_keys=True, separators=(",", ":"),
        ))
        expected.append(canonical_bytes(
            seq=case["seq"], timestamp=case["timestamp"], operator=case["operator"],
            action=case["action"], entry_hash=case["hash"],
        ).decode("utf-8"))

    assert len(js_output) == len(expected)
    for index, (got, want) in enumerate(zip(js_output, expected)):
        assert got == want, f"case {index // 2} canonical form diverged:\n  js: {got!r}\n  py: {want!r}"


@requires_node
def test_js_entry_hash_matches_a_real_backend_chain(tmp_path):
    chain = CustodyChain()
    chain.append("AETHER Pipeline", "Investigation initiated for case AT-2026-0047")
    chain.append("Lead Forensics Officer", 'Evidence hashed; note contains "quotes" and \\ backslash')
    chain.append("Lead Forensics Officer", "Dossier exported — नमस्ते 🚀")

    cases = [
        {
            "seq": e.seq, "timestamp": e.timestamp, "operator": e.actor, "action": e.action,
            "prev_hash": e.prev_hash, "hash": e.entry_hash,
        }
        for e in chain.entries
    ]
    js_output = _run_js(cases, tmp_path)
    entry_forms = js_output[0::2]

    import hashlib
    for entry, js_form in zip(chain.entries, entry_forms):
        assert hashlib.sha256(js_form.encode("utf-8")).hexdigest() == entry.entry_hash
        assert js_form == _canonical({
            "seq": entry.seq, "timestamp": entry.timestamp, "actor": entry.actor,
            "action": entry.action, "prev_hash": entry.prev_hash,
        }).decode("utf-8")


# --------------------------------------------------------------------------- #
# CSV parsing parity
# --------------------------------------------------------------------------- #

CSV_PARSER_HARNESS = r"""
/*__FUNCTIONS__*/

const fs = require("fs");
const text = fs.readFileSync(process.argv[2], "utf8");
const rows = parseCsv(text);
process.stdout.write(JSON.stringify({
  raw: rows,
  unescaped: rows.map((row) => row.map(unescapeCell)),
}));
"""


def _parse_csv_in_js(text: str, tmp_path: Path) -> dict:
    return json.loads(_run_node(CSV_PARSER_HARNESS, text, tmp_path))


@requires_node
def test_csv_parser_handles_rfc4180_quoting_identically_to_python(tmp_path):
    tricky = (
        '\ufeff"seq","operator","action","payload"\r\n'
        '"1","AETHER Pipeline","plain","simple"\r\n'
        '"2","Officer","contains, a comma","line1\nline2"\r\n'
        '"3","Officer","embedded ""quotes"" here","trailing "\r\n'
        '"4","Officer","unicode 🚀 नमस्ते","ok"\r\n'
    )
    js = _parse_csv_in_js(tricky, tmp_path)
    py_rows = list(csv.reader(io.StringIO(tricky.lstrip("\ufeff"))))

    # The embedded-newline row is one logical row in both parsers.
    assert len(js["raw"]) == len(py_rows) == 5
    for js_row, py_row in zip(js["raw"], py_rows):
        assert js_row == py_row
    assert js["unescaped"] == js["raw"], "no defused cells in this fixture"


@requires_node
def test_csv_parser_keeps_the_input_time_defuse_apostrophe(tmp_path):
    """A defused cell is hashed *with* its apostrophe, so the parser must not strip it.

    CustodyEntryCreate.sanitize_text prepends the apostrophe before the entry is
    ever hashed, which means stripping it here would report a clean ledger as
    tampered.
    """
    exported = (
        '"seq","operator","action","payload"\r\n'
        '"1","\'=cmd|calc","\'@SUM(A1)","\'-2+3"\r\n'
    )
    js = _parse_csv_in_js(exported, tmp_path)
    assert js["raw"][1] == ["1", "'=cmd|calc", "'@SUM(A1)", "'-2+3"]
    assert js["unescaped"][1] == ["1", "=cmd|calc", "@SUM(A1)", "-2+3"]


def test_unescape_only_touches_a_leading_apostrophe():
    """Only a *leading* apostrophe is export noise; internal ones are content."""
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    assert unescape_in_python("'=cmd") == "=cmd"
    assert unescape_in_python("it's fine") == "it's fine"
    assert unescape_in_python("'") == "'"
    assert unescape_in_python("") == ""


# --------------------------------------------------------------------------- #
# End-to-end: a real exported ledger verified by the extracted JS
# --------------------------------------------------------------------------- #

VERIFY_HARNESS = r"""
/*__FUNCTIONS__*/

const fs = require("fs");
const nodeCrypto = require("crypto");
globalThis.crypto = {
  subtle: {
    digest: async (algo, data) => {
      const hash = nodeCrypto.createHash("sha256");
      hash.update(Buffer.from(data));
      return hash.digest().buffer;
    },
  },
};

(async () => {
  const rows = toLedgerRows(parseCsv(fs.readFileSync(process.argv[2], "utf8")));
  const result = await verifyChain(rows, null);
  process.stdout.write(JSON.stringify({
    hashOk: result.hashOk,
    brokenAtSeq: result.brokenAtSeq,
    total: result.total,
    signedCount: result.signedCount,
  }));
})().catch((e) => { process.stderr.write(e.stack); process.exit(1); });
"""


def _verify_in_js(csv_text: str, tmp_path: Path) -> dict:
    return json.loads(_run_node(VERIFY_HARNESS, csv_text, tmp_path))


def _seed_ledger(client, actions: list[str]) -> str:
    """Create a case, append custody entries, and return the exported CSV."""
    created = client.post("/api/cases", json={
        "evidence_id": "AT-2026-0047",
        "actor_name": "Verifier Fixture",
        "aliases": ["FixtureAlias"],
    })
    assert created.status_code in (200, 201), created.text

    for action in actions:
        appended = client.post("/api/cases/AT-2026-0047/custody", json={
            "actor": "Lead Forensics Officer",
            "action": action,
        })
        assert appended.status_code == 201, appended.text

    exported = client.get("/api/cases/AT-2026-0047/export/custody")
    assert exported.status_code == 200, exported.text
    return exported.text


@requires_node
def test_exported_ledger_verifies_green_in_the_browser_verifier(client, tmp_path):
    csv_text = _seed_ledger(client, [
        "Investigation initiated",
        "Evidence hashed and sealed",
        "Dossier exported",
    ])

    result = _verify_in_js(csv_text, tmp_path)
    assert result["hashOk"] is True
    assert result["brokenAtSeq"] is None
    # The genesis hash is a virtual constant, not a stored row: three appends
    # produce three ledger rows starting at seq 1.
    assert result["total"] == 3


@requires_node
def test_tampered_ledger_verifies_red_at_the_edited_sequence(client, tmp_path):
    csv_text = _seed_ledger(client, ["alpha", "bravo", "charlie", "delta"])
    matrix = list(csv.reader(io.StringIO(csv_text.lstrip("\ufeff"))))
    action_col = matrix[0].index("action")

    # Edit a middle entry, exactly what a database attacker would do.
    for row in matrix[1:]:
        if row[action_col] == "charlie":
            row[action_col] = "charlie (amended after the fact)"

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerows(matrix)

    result = _verify_in_js("\ufeff" + buf.getvalue(), tmp_path)
    assert result["hashOk"] is False
    assert result["brokenAtSeq"] == 3


@requires_node
def test_recompute_attack_keeps_the_hash_chain_intact(client, tmp_path):
    """Editing a row AND re-hashing it still breaks the *next* link.

    The attacker's next step is to regenerate the downstream links too, which
    the following test covers.
    """
    import hashlib

    csv_text = _seed_ledger(client, ["alpha", "bravo", "charlie"])
    matrix = list(csv.reader(io.StringIO(csv_text.lstrip("\ufeff"))))
    idx = {name: matrix[0].index(name) for name in REQUIRED_COLUMNS}

    for row in matrix[1:]:
        if row[idx["action"]] == "bravo":
            row[idx["action"]] = "bravo (amended)"
            payload = {
                "seq": int(row[idx["seq"]]),
                "timestamp": row[idx["timestamp_utc"]],
                "actor": row[idx["operator"]],
                "action": row[idx["action"]],
                "prev_hash": row[idx["prev_hash"]],
            }
            row[idx["hash"]] = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            break

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerows(matrix)

    result = _verify_in_js("\ufeff" + buf.getvalue(), tmp_path)
    assert result["hashOk"] is False
    assert result["brokenAtSeq"] == 3


@requires_node
def test_recompute_attack_with_fully_regenerated_chain_passes_the_hash_layer(client, tmp_path):
    """A complete rewrite of k..n is invisible to the hash layer by design.

    This test documents the limitation rather than pretending the hash chain is
    sufficient: it is precisely why verify.html offers the Ed25519 signature
    check, and why the exported column list includes signature and key_id.
    """
    import hashlib

    csv_text = _seed_ledger(client, ["alpha", "bravo", "charlie"])
    matrix = list(csv.reader(io.StringIO(csv_text.lstrip("\ufeff"))))
    idx = {name: matrix[0].index(name) for name in REQUIRED_COLUMNS}
    rows = matrix[1:]

    for row in rows:
        if row[idx["action"]] == "bravo":
            row[idx["action"]] = "bravo (amended)"

    prev = GENESIS_HASH
    for row in rows:
        row[idx["prev_hash"]] = prev
        payload = {
            "seq": int(row[idx["seq"]]),
            "timestamp": row[idx["timestamp_utc"]],
            "actor": row[idx["operator"]],
            "action": row[idx["action"]],
            "prev_hash": row[idx["prev_hash"]],
        }
        row[idx["hash"]] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        prev = row[idx["hash"]]

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerows(matrix)

    result = _verify_in_js("\ufeff" + buf.getvalue(), tmp_path)
    assert result["hashOk"] is True, "the hash layer alone cannot detect a full re-hash"
    assert result["signedCount"] == 0, "and with no signatures there is nothing left to catch it"
