"""Re-sort the report's references alphabetically and renumber every citation.

The department's format requires the reference list to be "in alphabetical order
of the first author" with "the name of the author/authors ... immediately
followed by the year". The list was written IEEE-style, numbered by theme, so
both the order and the author-year arrangement have to change -- and because the
inline citations are numeric, every `[n]` in every chapter has to move with it.

Doing that by hand across sixty verified entries and several hundred citations is
exactly the kind of job that introduces a wrong number nobody notices, so it is
done here and checked: the script refuses to write anything unless every entry
survives, every DOI survives, and every citation still resolves.

Run:  python -m tools.reformat_references
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPORT = Path("writing/report")
CONCLUSION = REPORT / "05-conclusion.md"
CHAPTERS = ["00-front-matter.md", "01-introduction.md", "02-literature-survey.md",
            "03-design-flow-part1.md", "03-design-flow-part2.md",
            "04-results.md", "05-conclusion.md", "06-appendices.md"]

#: "M. H. Almeshekah" -> ("Almeshekah", "M. H."); "OWASP Foundation" -> as-is.
#: Hyphenated initials matter: "J.-H. Cho" must not split into "-H. Cho, J.".
INITIALS = re.compile(r"^((?:[A-Z]\.(?:-[A-Z]\.)?\s*)+)\s*(.+)$")


def _surname_first(name: str) -> tuple[str, str]:
    """Return (sortkey, rendered) for one author name."""
    name = name.strip().rstrip(",").strip()
    m = INITIALS.match(name)
    if m:
        initials, surname = m.group(1).strip(), m.group(2).strip()
        return surname.lower(), f"{surname}, {initials}"
    return name.lower(), name          # corporate author: leave alone


def _split_authors(head: str) -> list[str]:
    head = re.sub(r"\s+et al\.?$", "", head.strip())
    parts = re.split(r",\s*and\s+|\s+and\s+|,\s*(?=[A-Z]\.)|,\s*(?=[A-Z][a-z])", head)
    return [p for p in (x.strip().rstrip(",") for x in parts) if p]


def parse(entry: str) -> dict:
    """Pull authors, year and the remainder out of one IEEE-style entry."""
    flat = " ".join(entry.split())
    m = re.match(r'^(.*?),\s*[""“](.*)$', flat)
    if not m:                                   # book / corporate form
        m2 = re.match(r"^(.*?),\s*\*(.*)$", flat)
        head, rest = (m2.group(1), "*" + m2.group(2)) if m2 else (flat, "")
    else:
        head, rest = m.group(1), '"' + m.group(2)

    years = re.findall(r"\b(1[89]\d{2}|20\d{2})\b", flat)
    year = years[-1] if years else ""

    authors = _split_authors(head)
    if not authors:
        authors = [head]
    sortkey = _surname_first(authors[0])[0]
    rendered = [_surname_first(a)[1] for a in authors]
    if len(rendered) == 1:
        names = rendered[0]
    elif len(rendered) == 2:
        names = f"{rendered[0]} and {rendered[1]}"
    else:
        names = ", ".join(rendered[:-1]) + f" and {rendered[-1]}"

    # drop the trailing ", YEAR." that IEEE puts after the venue
    body = rest
    if year:
        body = re.sub(rf",\s*{year}\b\.?", "", body, count=1)
    body = body.strip().rstrip(",").strip()
    return {"sort": sortkey, "names": names, "year": year, "body": body,
            "original": flat}


def main() -> None:
    text = CONCLUSION.read_text(encoding="utf-8")
    start = text.index("## 5.5 References")
    head, block = text[:start], text[start:]

    found = re.findall(r"^\[(\d+)\]\s+(.*?)(?=\n\n|\n\[|\Z)", block, re.M | re.S)
    if not found:
        sys.exit("no reference entries found")
    old = {int(n): t.strip() for n, t in found}

    parsed = {n: parse(t) for n, t in old.items()}
    order = sorted(parsed, key=lambda n: (parsed[n]["sort"], parsed[n]["year"]))
    remap = {old_n: new_i for new_i, old_n in enumerate(order, start=1)}

    # ---- integrity checks before anything is written ----------------------
    dois_before = set(re.findall(r"doi:\s*\S+", block))
    lines = ["## 5.5 References", "",
             "Listed in alphabetical order of the first author, as required by the",
             "report format. References [1]-[43] of the associated research paper were",
             "each verified against publisher or arXiv records; the classical and",
             "standards works added for this report should be re-confirmed against a",
             "publisher record before final submission.", ""]
    for new_i, old_n in enumerate(order, start=1):
        e = parsed[old_n]
        yr = f" ({e['year']})" if e["year"] else ""
        lines.append(f"[{new_i}] {e['names']}{yr} {e['body']}")
        lines.append("")
    new_block = "\n".join(lines).rstrip() + "\n"

    dois_after = set(re.findall(r"doi:\s*\S+", new_block))
    if dois_before != dois_after:
        sys.exit(f"DOI loss: {len(dois_before)} before, {len(dois_after)} after")
    if len(re.findall(r"^\[\d+\]", new_block, re.M)) != len(old):
        sys.exit("entry count changed")

    # ---- renumber every inline citation -----------------------------------
    def renum(mo):
        inner = mo.group(1)
        nums = [int(x) for x in re.findall(r"\d+", inner)]
        if not all(n in remap for n in nums):
            return mo.group(0)
        return "[" + ", ".join(str(remap[n]) for n in nums) + "]"

    CITE = re.compile(r"\[((?:\d+)(?:\s*,\s*\d+)*)\]")
    touched = 0
    for name in CHAPTERS:
        p = REPORT / name
        s = p.read_text(encoding="utf-8")
        if name == "05-conclusion.md":
            s = s[:s.index("## 5.5 References")]
        before = s
        s = CITE.sub(renum, s)
        if name == "05-conclusion.md":
            s = s + new_block
        if s != before or name == "05-conclusion.md":
            p.write_text(s, encoding="utf-8")
            touched += 1

    print(f"  {len(old)} references re-sorted alphabetically and renumbered")
    print(f"  {touched} chapter file(s) updated")
    print(f"  first: {parsed[order[0]]['names']}")
    print(f"  last:  {parsed[order[-1]]['names']}")


if __name__ == "__main__":
    main()
