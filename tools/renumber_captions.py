"""Renumber figures and tables into document order, and fix every reference.

Word's caption feature numbers by position: a SEQ field counts captions as it
meets them. The report's captions were numbered by the order the material was
written in, which is not the order it is read in -- Figure 26 sits between
Figure 7 and Figure 8, and Table 1 comes after Table 2. Inserting SEQ fields
without fixing that would silently repoint every "see Figure 5" in the prose.

So this renumbers first. It reads the assembled document to establish true
reading order, then rewrites captions, in-text references ("Figure 12",
"Tables 4 and 5", "Fig. 1") and the front-matter lists in one simultaneous
substitution -- sequential replacement would collide, since some new numbers are
also old numbers.

Run:  python -m tools.renumber_captions
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPORT = Path("writing/report")
ASSEMBLED = REPORT / "PROJECT_REPORT.md"
CHAPTERS = ["00-front-matter.md", "01-introduction.md", "02-literature-survey.md",
            "03-design-flow-part1.md", "03-design-flow-part2.md",
            "04-results.md", "05-conclusion.md", "06-appendices.md"]


def reading_order(kind: str) -> list[int]:
    """Caption numbers in the order a reader meets them, ignoring the lists."""
    text = ASSEMBLED.read_text(encoding="utf-8")
    body = text[text.index("CHAPTER 1"):]        # skip the front-matter lists
    return [int(m.group(1)) for m in re.finditer(rf"\*\*{kind} (\d+):", body)]


def build_map(kind: str) -> dict[int, int]:
    order = reading_order(kind)
    if len(set(order)) != len(order):
        sys.exit(f"duplicate {kind} numbers in the document: cannot renumber safely")
    return {old: new for new, old in enumerate(order, start=1)}


def apply(text: str, kind: str, mapping: dict[int, int]) -> str:
    """Rewrite captions and references for one kind, all at once."""
    short = "Fig." if kind == "Figure" else "Table"

    # placeholders so a new number never collides with an old one mid-pass
    def token(n: int) -> str:
        return f"\x00{kind[0]}{mapping[n]}\x00"

    # "**Figure 12:" and "**Table 3:"
    text = re.sub(rf"\*\*{kind} (\d+):",
                  lambda m: f"**{kind} {token(int(m.group(1)))}:"
                  if int(m.group(1)) in mapping else m.group(0), text)

    # "Figure 12", "Figures 1, 12, 15 and 17", "Fig. 1", "Table 24", "Tables 4 and 5"
    plural = f"{kind}s" if kind == "Figure" else "Tables"
    pat = rf"\b(?:{kind}s?|{re.escape(short)})\s+((?:\d+)(?:\s*(?:,|and|–|-)\s*\d+)*)"

    def fix(m: str) -> str:
        whole = m.group(0)
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        if not all(n in mapping for n in nums):
            return whole
        out = whole
        for n in sorted(nums, reverse=True):     # longest first avoids partial hits
            out = re.sub(rf"\b{n}\b", token(n), out, count=1)
        return out

    text = re.sub(pat, fix, text)
    return text


def main() -> None:
    if not ASSEMBLED.exists():
        sys.exit("run `python -m tools.build_report` first")

    maps = {k: build_map(k) for k in ("Figure", "Table")}
    for k, m in maps.items():
        moved = sum(1 for a, b in m.items() if a != b)
        print(f"  {k}s: {len(m)} captions, {moved} renumbered")

    for name in CHAPTERS:
        p = REPORT / name
        s = p.read_text(encoding="utf-8")
        for kind, mapping in maps.items():
            s = apply(s, kind, mapping)
        # resolve placeholders
        s = re.sub(r"\x00[FT](\d+)\x00", r"\1", s)
        p.write_text(s, encoding="utf-8")

    print("  chapters rewritten; rebuild to verify order")


if __name__ == "__main__":
    main()
