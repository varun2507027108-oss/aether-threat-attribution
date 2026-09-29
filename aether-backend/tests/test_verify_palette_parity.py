"""The verifier's palette must equal the console's, for both themes.

verify.html duplicates the console's tokens by hand, with the --color- prefix
stripped, because it has to be a single self-contained file that works from a
file:// URL with no network. That is a legitimate reason to duplicate and also a
reliable way for the two to drift: the existing tests pinned a hand-listed set
of literals, so retuning the console's light theme could leave the verifier
sitting on the old values with every test still green -- and a statutory
certificate is exactly the artefact that must not look like a different product
from the one that produced it.

So this file reads globals.css, derives what the verifier ought to say, and
asserts that it does. Add a token to the console and this test says which
verifier entry is missing; change one value in only one of the two files and it
names the token.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
VERIFY_HTML = REPO / "verify.html"
FRONTEND_COPY = REPO / "aether-frontend" / "public" / "verify.html"
GLOBALS_CSS = REPO / "aether-frontend" / "src" / "app" / "globals.css"

# Graph-only tokens. The verifier draws a custody chain, not a knowledge graph,
# so these are intentionally not carried across; asserting them would push
# unused colours into an air-gapped file.
GRAPH_ONLY_PREFIXES = ("--color-node-", "--color-link-")


def _block(text: str, selector: str) -> str:
    start = text.index(selector)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise AssertionError(f"unterminated block for {selector}")


def _console_tokens(css: str, selector: str) -> dict[str, str]:
    body = _block(css, selector)
    found = dict(re.findall(r"(--color-[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;", body))
    return {k: v for k, v in found.items() if not k.startswith(GRAPH_ONLY_PREFIXES)}


def _verifier_tokens(html: str, *, light: bool) -> dict[str, str]:
    """Read the verifier's own token table, dark or light."""
    if light:
        body = _block(html, "@media (prefers-color-scheme: light)")
    else:
        body = _block(html, ":root {")
    body = _block(body, ":root") if body.lstrip().startswith("@media") else body
    found = re.findall(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;", body)
    # The shorthand entries (--border, --border-soft) hold a full border value
    # rather than a colour and are not part of the mirrored palette.
    return {k: v for k, v in found if v.startswith("#")}


@pytest.fixture(scope="module")
def css() -> str:
    return GLOBALS_CSS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def html() -> str:
    return VERIFY_HTML.read_text(encoding="utf-8")


def test_the_console_defines_both_themes(css: str):
    """Guard the premise of the rest of this file.

    If the light block were renamed or removed, every comparison below would
    raise on a missing selector and report as a collection of confusing
    failures rather than as the one real problem.
    """
    assert ':root[data-theme="light"]' in css
    assert len(_console_tokens(css, "@theme")) >= 35
    assert len(_console_tokens(css, ':root[data-theme="light"]')) >= 35


@pytest.mark.parametrize("light", [False, True], ids=["dark", "light"])
def test_every_console_token_reaches_the_verifier(css, html, light):
    """A token the console has and the verifier lacks.

    Usually this means a token was added to the console and not mirrored. The
    verifier then falls back to an unset custom property, which resolves to
    nothing at all rather than to a sensible colour -- a card with no
    background, a border with no colour -- so this is a visible break, not a
    cosmetic one.
    """
    selector = ':root[data-theme="light"]' if light else "@theme"
    console = _console_tokens(css, selector)
    verifier = _verifier_tokens(html, light=light)
    missing = sorted(
        f"--{name.replace('--color-', '')}: {value}"
        for name, value in console.items()
        if f"--{name.replace('--color-', '')}" not in verifier
    )
    assert not missing, (
        f"verify.html {'light' if light else 'dark'} block is missing console "
        f"tokens: {missing}"
    )


@pytest.mark.parametrize("light", [False, True], ids=["dark", "light"])
def test_every_verifier_token_matches_the_console(css, html, light):
    """A token both files have, with different values.

    This is the failure that matters most and the one the previous hand-written
    assertions could not catch: the verifier keeps rendering its own idea of
    the product while the console has moved on. Both files are green, the
    certificate still validates, and the two artefacts simply no longer match.
    """
    selector = ':root[data-theme="light"]' if light else "@theme"
    console = _console_tokens(css, selector)
    verifier = _verifier_tokens(html, light=light)

    mismatched = []
    for name, value in sorted(console.items()):
        short = f"--{name.replace('--color-', '')}"
        if short in verifier and verifier[short].lower() != value.lower():
            mismatched.append(
                f"{short}: verifier {verifier[short]} vs console {value}"
            )
    assert not mismatched, (
        f"verify.html {'light' if light else 'dark'} block has drifted from "
        f"globals.css: {mismatched}"
    )


def test_verify_html_offers_both_themes(html: str):
    assert "@media (prefers-color-scheme: light)" in html, (
        "the verifier must follow the reader's OS theme; a statutory document "
        "gets read in lit rooms and printed into binders, not only in a dark SOC"
    )


def test_the_light_block_comes_after_the_base_block(html: str):
    """Specificity, checked rather than assumed.

    A plain :root in a media query and a plain :root outside it have identical
    specificity, so source order is the only thing separating them. Putting the
    media query first would silently do nothing and every value above it would
    win.

    The comparison is on the selectors themselves rather than on the string
    "prefers-color-scheme", because the explanatory comment above the block
    also contains that phrase and matching on it would assert nothing.
    """
    base = html.index(":root {")
    override = html.index("@media (prefers-color-scheme: light) {")
    assert base < override, "the light override must follow the base :root block"


def test_both_verifier_copies_still_match_each_other():
    assert VERIFY_HTML.read_bytes() == FRONTEND_COPY.read_bytes(), (
        "verify.html and aether-frontend/public/verify.html have diverged; "
        "edit the root copy then copy it across"
    )
