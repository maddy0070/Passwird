#!/usr/bin/env python3
"""
WCAG contrast check over the design tokens.

`docs/08-design-system.md` §2.3 commits to a 4.5:1 floor for all text — including
`textTertiary`, which is the one most likely to fail — and 3:1 for borders and icons that
carry meaning. It also says this is "verified by test, not by eye".

That test did not exist. The design document named a `ContrastTest`, and an audit found
nothing implementing it, so the accessibility commitment was unverified.

This is it. It parses the palettes straight out of `Color.kt` — the same file the app
compiles — rather than duplicating the values, so the check cannot drift from the tokens
it is checking.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLOR_FILE = ROOT / "design/tokens/src/main/kotlin/com/passwird/design/tokens/Color.kt"

TEXT_FLOOR = 4.5
NON_TEXT_FLOOR = 3.0

# Every surface a foreground can actually land on has to be listed. The first version of
# this file checked `textTertiary` only against `ground` and `surface` — and missed that
# placeholders render inside a `surfaceSunken` input well, which is the worst case in light
# mode. A contrast check is only as good as its pair list, so these follow the components.
ALL_SURFACES = ("ground", "surface", "surfaceRaised", "surfaceSunken")

# (foreground, background, floor, what it is)
TEXT_PAIRS = [
    ("textPrimary", "ground", TEXT_FLOOR, "body text on the app background"),
    ("textPrimary", "surface", TEXT_FLOOR, "body text on a sheet"),
    ("textPrimary", "surfaceRaised", TEXT_FLOOR, "body text on a pressed row"),
    ("textPrimary", "surfaceSunken", TEXT_FLOOR, "text in an input well"),
    ("textSecondary", "ground", TEXT_FLOOR, "labels and metadata"),
    ("textSecondary", "surface", TEXT_FLOOR, "labels on a sheet"),
    ("textSecondary", "surfaceRaised", TEXT_FLOOR, "a chip label when selected"),
    ("textSecondary", "surfaceSunken", TEXT_FLOOR, "helper text under a field"),
    ("textTertiary", "ground", TEXT_FLOOR, "timestamps in a list"),
    ("textTertiary", "surface", TEXT_FLOOR, "tertiary text on a sheet"),
    ("textTertiary", "surfaceRaised", TEXT_FLOOR, "tertiary text on a pressed row"),
    ("textTertiary", "surfaceSunken", TEXT_FLOOR, "a field placeholder, inside its well"),
    ("signal", "ground", TEXT_FLOOR, "the 'Synced' label"),
    ("signal", "surface", TEXT_FLOOR, "the sync pill"),
    ("attention", "ground", TEXT_FLOOR, "'Needs review'"),
    ("attention", "surface", TEXT_FLOOR, "the attention banner"),
    ("danger", "ground", TEXT_FLOOR, "'Sync failed'"),
    ("danger", "surface", TEXT_FLOOR, "the danger banner"),
    ("textInverse", "textPrimary", TEXT_FLOOR, "the primary button's label on its fill"),
]

NON_TEXT_PAIRS = [
    # The secondary button has no fill, so this border is the component's only boundary;
    # the same token marks a focused field and a selected chip. All are 1.4.11 cases.
    *[
        ("borderInteractive", s, NON_TEXT_FLOOR, f"a control's boundary or focus, on {s}")
        for s in ALL_SURFACES
    ],
    ("focusRing", "ground", NON_TEXT_FLOOR, "the keyboard focus ring"),
    ("danger", "surface", NON_TEXT_FLOOR, "the destructive button's border"),
    ("signal", "ground", NON_TEXT_FLOOR, "the sealed glyph"),
    ("attention", "ground", NON_TEXT_FLOOR, "the attention glyph"),
    ("danger", "ground", NON_TEXT_FLOOR, "the danger glyph"),
]

# `line` and `lineStrong` are deliberately absent. They are decorative rules between rows
# and sections; WCAG 1.4.11 exempts decoration, and a hairline loud enough to pass would
# defeat the point of the system. Anything that identifies a control uses the token above.


def parse_palettes(text: str) -> dict[str, dict[str, str]]:
    """Extracts `val DarkColors = PasswirdColors( ... )` blocks into name -> hex maps."""
    palettes: dict[str, dict[str, str]] = {}
    for match in re.finditer(r"val (\w+Colors) = PasswirdColors\((.*?)\n\)", text, re.S):
        name, body = match.group(1), match.group(2)
        tokens = {}
        for token, hexvalue in re.findall(r"(\w+)\s*=\s*Color\(0x([0-9A-Fa-f]{8})\)", body):
            tokens[token] = hexvalue[2:]  # drop the alpha byte
        palettes[name] = tokens
    return palettes


def channel(value: int) -> float:
    srgb = value / 255.0
    return srgb / 12.92 if srgb <= 0.04045 else ((srgb + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_rgb: str) -> float:
    r, g, b = (int(hex_rgb[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = relative_luminance(a), relative_luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def check(palette_name: str, tokens: dict[str, str], pairs, kind: str) -> list[str]:
    failures = []
    for fg, bg, floor, description in pairs:
        if fg not in tokens or bg not in tokens:
            failures.append(f"{palette_name}: token missing for {fg} on {bg}")
            continue
        ratio = contrast(tokens[fg], tokens[bg])
        status = "ok  " if ratio >= floor else "FAIL"
        line = f"  {status} {palette_name:12s} {fg:15s} on {bg:14s} {ratio:5.2f}:1  (>= {floor})  {description}"
        print(line)
        if ratio < floor:
            failures.append(
                f"{palette_name}: {fg} on {bg} is {ratio:.2f}:1, below the {floor}:1 floor for {kind} ({description})"
            )
    return failures


def main() -> int:
    if not COLOR_FILE.exists():
        print(f"FAIL  cannot find {COLOR_FILE.relative_to(ROOT)}")
        return 1

    palettes = parse_palettes(COLOR_FILE.read_text())
    if {"DarkColors", "LightColors"} - palettes.keys():
        print(f"FAIL  expected DarkColors and LightColors, found {sorted(palettes)}")
        return 1

    print("Design token contrast (WCAG 2.1)")
    print("--------------------------------")

    failures: list[str] = []
    for name in ("DarkColors", "LightColors"):
        print(f"\n{name} — text")
        failures += check(name, palettes[name], TEXT_PAIRS, "text")
        print(f"\n{name} — non-text")
        failures += check(name, palettes[name], NON_TEXT_PAIRS, "meaningful non-text")

    print()
    if failures:
        print(f"FAIL  {len(failures)} pair(s) below the documented floor:")
        for f in failures:
            print(f"      {f}")
        return 1

    total = (len(TEXT_PAIRS) + len(NON_TEXT_PAIRS)) * 2
    print(f"PASS  {total} colour pairs meet the floors in docs/08-design-system.md §2.3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
