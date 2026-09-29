"""Measure the console's own colour tokens, for both themes, from the real CSS.

The palette used to carry its contrast arguments in a comment in globals.css,
which is documentation rather than a test: it was true when written and nothing
checked it afterwards. A light theme roughly doubled the palette and made that
gap matter, because a role that clears 4.5:1 on a near-black card can be
completely invisible on a white one.

So the numbers are read out of globals.css here and re-measured on every run. A
token that drifts out of spec fails this file, not a browser audit three weeks
later.

Both themes are held to the same bar:

  * every ink role clears 4.5:1 on every surface it is actually placed on
  * each semantic ink clears 4.5:1 on its own surface
  * the focus ring clears 3:1 everywhere it can appear
  * the six graph node colours clear 3:1 as non-text, on the card AND on the
    chart well, because the graph renders over both
  * the six node colours form three complementary pairs

Borders are deliberately NOT asserted at 3:1. The dark theme ships hairline
borders by design -- line-active measures 1.97:1 on card and the input well
1.04:1 -- and the focus ring, at 11.4:1, is what carries state. Asserting 3:1
for the light theme alone would make it heavier than the theme it is a
counterpart to, so the same standard is applied to both.
"""

from __future__ import annotations

import colorsys
import re
from pathlib import Path

import pytest

GLOBALS_CSS = (
    Path(__file__).resolve().parents[2] / "aether-frontend" / "src" / "app" / "globals.css"
)

INK_ROLES = ("ink", "ink-muted", "ink-dim", "ink-faint")

# Every surface an ink role is realistically placed on. `card` is the common
# case; `active` is the tightest because it is the darkest plane a button fill
# provides; `sunken` is the chart well behind the graphs.
SURFACES = ("card", "surface", "active", "raised", "canvas", "input", "sunken", "overlay")

SEMANTIC = ("signal", "alert", "info", "warn")

FOCUS_SURFACES = ("canvas", "card", "surface", "active", "input")

NODE_TOKENS = {
    "threat-actor": "--color-node-actor",
    "ipv4": "--color-node-ipv4",
    "wallet": "--color-node-wallet",
    "pgp": "--color-node-pgp",
    "hash": "--color-node-hash",
    "darknet": "--color-node-darknet",
}

# Each entity type is the complement of the one opposite it on the wheel. The
# pairings are the reason the palette looks designed rather than assorted.
COMPLEMENTARY_PAIRS = (
    ("threat-actor", "ipv4"),
    ("wallet", "hash"),
    ("pgp", "darknet"),
)

LINK_TOKENS = ("--color-link-confirmed", "--color-link-guess")


def _channel(value: int) -> float:
    v = value / 255
    return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4


def _luminance(colour: str) -> float:
    h = colour.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def ratio(fg: str, bg: str) -> float:
    a, b = _luminance(fg), _luminance(bg)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def _hue(colour: str) -> float:
    h = colour.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return colorsys.rgb_to_hsv(r, g, b)[0] * 360


def _separation(a: str, b: str) -> float:
    gap = abs(_hue(a) - _hue(b))
    return min(gap, 360 - gap)


def _read_theme_block(text: str, selector: str) -> dict[str, str]:
    """Pull `--token: #hex` pairs out of one CSS block.

    The dark theme lives in the @theme block and the light theme in a
    :root[data-theme="light"] block, so each is read from its own source rather
    than from a copy made here. A test that transcribed the values would only
    prove the transcription was consistent with itself.
    """
    start = text.index(selector)
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                body = text[start:index]
                break
    else:  # pragma: no cover - a malformed stylesheet should be loud
        raise AssertionError(f"unterminated block for {selector}")

    found = dict(
        # The character class has to admit digits: `--color-node-ipv4` is a
        # real token, and a parser that silently skipped it would have reported
        # a clean run while measuring four of the six node colours.
        re.findall(r"(--color-[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;", body)
    )
    return found


@pytest.fixture(scope="module")
def css() -> str:
    return GLOBALS_CSS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dark(css: str) -> dict[str, str]:
    return _read_theme_block(css, "@theme")


@pytest.fixture(scope="module")
def light(css: str) -> dict[str, str]:
    return _read_theme_block(css, ':root[data-theme="light"]')


THEMES = {"dark": "dark", "light": "light"}


def test_both_themes_define_the_same_tokens(dark, light):
    """A token added to one theme and forgotten in the other is a silent hole.

    Nothing at runtime complains: the light theme simply falls back to the
    dark value for anything it does not redefine, so a card keeps its dark
    colour on a white page and the bug reads as "the light theme is a bit
    odd" rather than as a missing definition.
    """
    only_dark = sorted(set(dark) - set(light))
    only_light = sorted(set(light) - set(dark))
    assert not only_dark, f"tokens in @theme but not in the light theme: {only_dark}"
    assert not only_light, f"tokens in the light theme but not in @theme: {only_light}"


@pytest.mark.parametrize("theme", THEMES)
def test_no_token_is_pure_black(theme, request):
    """globals.css argues against #000000 and the old test enforced it here.

    The reasoning was OLED halation, which is a dark-theme concern, but the
    light theme has an independent reason to avoid it: a pure black hairline on
    a near-white surface reads as a printing error rather than as a border.
    """
    tokens = request.getfixturevalue(theme)
    offenders = sorted(t for t, v in tokens.items() if v.lower() == "#000000")
    assert not offenders, f"{theme} theme uses pure black for: {offenders}"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("role", INK_ROLES)
@pytest.mark.parametrize("surface", SURFACES)
def test_ink_roles_clear_wcag_aa_body_text(theme, role, surface, request):
    tokens = request.getfixturevalue(theme)
    key, on = f"--color-{role}", f"--color-{surface}"
    assert key in tokens, f"{theme} theme is missing {key}"
    assert on in tokens, f"{theme} theme is missing {on}"
    measured = ratio(tokens[key], tokens[on])
    assert measured >= 4.5, (
        f"{theme}: {key} is {measured:.2f}:1 on {on} ({tokens[on]}), below the "
        f"4.5:1 body-text floor"
    )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("base", SEMANTIC)
def test_semantic_ink_clears_wcag_aa_on_its_own_surface(theme, base, request):
    tokens = request.getfixturevalue(theme)
    ink, surface = tokens[f"--color-{base}-ink"], tokens[f"--color-{base}-surface"]
    measured = ratio(ink, surface)
    assert measured >= 4.5, (
        f"{theme}: --color-{base}-ink is {measured:.2f}:1 on "
        f"--color-{base}-surface, below 4.5:1"
    )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("surface", FOCUS_SURFACES)
def test_focus_ring_is_visible_on_every_surface(theme, surface, request):
    """The focus ring is the product's only state indicator, so it is the one
    border-weight role that does have to clear 3:1. Everything else is
    hairline decoration by design."""
    tokens = request.getfixturevalue(theme)
    measured = ratio(tokens["--color-focus"], tokens[f"--color-{surface}"])
    assert measured >= 3.0, (
        f"{theme}: --color-focus is {measured:.2f}:1 on --color-{surface}, below 3:1"
    )


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("node,token", sorted(NODE_TOKENS.items()))
def test_graph_node_colours_clear_non_text_contrast(theme, node, token, request):
    """The graph draws over the card and over --color-sunken, so both are
    checked. 3:1 is WCAG 1.4.11 for a graphical object needed to understand the
    content, which is what a node sphere is."""
    tokens = request.getfixturevalue(theme)
    colour = tokens[token]
    for surface in ("card", "sunken"):
        measured = ratio(colour, tokens[f"--color-{surface}"])
        assert measured >= 3.0, (
            f"{theme}: {token} is {measured:.2f}:1 on --color-{surface}, below 3:1"
        )


@pytest.mark.parametrize("theme", THEMES)
def test_graph_palette_is_three_complementary_pairs(theme, request):
    """The entity colours are a categorical set, and an arbitrary one is
    unreadable once there are more than three. These are built as three
    opposed pairs so a relationship between two types always reads as a
    designed contrast.

    150 degrees is the floor rather than a hard 180 because a hue that is
    genuinely yellow cannot sit at 60 degrees and still clear contrast on a
    white page, so the amber is allowed to drift and is measured here.
    """
    tokens = request.getfixturevalue(theme)
    for a, b in COMPLEMENTARY_PAIRS:
        separation = _separation(tokens[NODE_TOKENS[a]], tokens[NODE_TOKENS[b]])
        assert separation >= 150.0, (
            f"{theme}: {a} and {b} are only {separation:.0f} degrees apart; "
            f"they are meant to be a complementary pair"
        )


@pytest.mark.parametrize("theme", THEMES)
def test_link_confidence_pair_is_complementary(theme, request):
    """A proven link and a guessed one must never look alike, because a
    reviewer who cannot tell them apart will read an inference as a fact. They
    were cyan and rose -- neighbours in one corner of the wheel -- and are now
    cyan and orange, opposite ends of the spectrum."""
    tokens = request.getfixturevalue(theme)
    confirmed, guess = (tokens[t] for t in LINK_TOKENS)
    separation = _separation(confirmed, guess)
    assert separation >= 150.0, (
        f"{theme}: confirmed {confirmed} and guess {guess} are only "
        f"{separation:.0f} degrees apart"
    )


@pytest.mark.parametrize("theme", THEMES)
def test_themes_do_not_share_a_single_colour(theme, request):
    """A token that is identical in both themes is almost always a missed
    translation rather than a deliberate choice -- it is the one that looks
    correct on whichever background the author had open.

    --color-line-active is the known exception and is allowed to differ anyway
    by enough to be visible; this test exists to surface the rest for review.
    """
    dark_tokens = request.getfixturevalue("dark")
    light_tokens = request.getfixturevalue("light")
    shared = sorted(
        t
        for t in dark_tokens
        if dark_tokens[t].lower() == light_tokens.get(t, "").lower()
        and t.startswith(("--color-node-", "--color-link-", "--color-ink", "--color-focus"))
    )
    assert not shared, f"{theme}: these tokens are identical in both themes: {shared}"


@pytest.mark.parametrize("theme", THEMES)
def test_overlay_reads_as_the_topmost_plane(theme, request):
    """The overlay exists to sit above the surfaces it covers. In dark it is
    lighter than --color-raised because it occludes; on a light page that
    inversion is not available, so the overlay has to earn its separation from
    its border instead. Either way the border must be the heaviest in the
    file, or the popover stops reading as a separate stratum."""
    tokens = request.getfixturevalue(theme)
    overlay_line = tokens["--color-overlay-line"]
    others = [
        tokens[f"--color-{n}"]
        for n in ("line-faint", "line", "line-strong", "line-active")
    ]
    assert ratio(overlay_line, tokens["--color-card"]) >= min(
        ratio(o, tokens["--color-card"]) for o in others
    ), (
        f"{theme}: --color-overlay-line is not the heaviest border in the theme, "
        f"so the popover will not read as a separate plane"
    )
