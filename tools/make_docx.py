"""Convert the assembled Markdown report into a .docx file.

There is no pandoc on this machine, so the conversion is done directly with
python-docx. Doing it by hand is not as bad as it sounds and buys control over the
things that matter for a submitted report: table style, caption formatting, image
sizing, and where the page breaks fall.

What it handles:
  * headings (# .. ######), with chapter headings starting a new page
  * paragraphs with **bold**, *italic*, `code` and [links](x) flattened to text
  * bullet and numbered lists, including nested levels
  * tables, with a header row and the document's table style
  * images -- SVG references are redirected to the PNG renders, since Word will
    not embed SVG reliably
  * fenced code blocks and the numbered algorithm listings, in a shaded monospace
    style
  * ```mermaid blocks, replaced by the rendered PNG of that diagram
  * block quotes
  * the explicit page-break markers inserted by tools/build_report.py

Run:  python -m tools.make_docx        ->  docs/PROJECT_REPORT.docx
"""
from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

SRC = Path("writing/report/PROJECT_REPORT.md")
OUT = Path("writing/report/PROJECT_REPORT.docx")
PNG = Path("writing/figures/png")
DIAGRAM_PNG = Path("writing/figures/diagrams")
DIAGRAMS = Path("writing/diagrams")

BODY_FONT = "Times New Roman"
MONO_FONT = "Consolas"
MAX_IMG_IN = 6.1          # printable width inside 1-inch margins on A4


# --------------------------------------------------------------- helpers ----
def _shade(paragraph, hex_fill: str) -> None:
    pr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    pr.append(shd)


def _border_box(paragraph) -> None:
    pr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    for side in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:space"), "4")
        el.set(qn("w:color"), "C9C9C9")
        borders.append(el)
    pr.append(borders)


INLINE = re.compile(
    r"(\*\*.+?\*\*|\*[^*\n]+?\*|`[^`]+?`|\[[^\]]+?\]\([^)]+?\))", re.S)


def _add_runs(par, text: str, base_size: float = 11.0) -> None:
    """Write text into a paragraph, honouring bold / italic / code / links."""
    text = text.replace("\\_", "_")
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            r = par.add_run(part[2:-2]); r.bold = True
        elif (part.startswith("*") and part.endswith("*")
              and len(part) > 2 and not part.startswith("**")):
            r = par.add_run(part[1:-1]); r.italic = True
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            r = par.add_run(part[1:-1])
            r.font.name = MONO_FONT
            r.font.size = Pt(base_size - 1.5)
            r.font.color.rgb = RGBColor(0x8B, 0x1A, 0x1A)
        elif part.startswith("[") and "](" in part:
            label = part[1:part.index("](")]
            r = par.add_run(label)
            r.font.color.rgb = RGBColor(0x1F, 0x4E, 0x79)
        else:
            r = par.add_run(part)
        if r.font.name is None:
            r.font.name = BODY_FONT
        if r.font.size is None:
            r.font.size = Pt(base_size)


def _image_for(ref: str) -> Path | None:
    """Map a Markdown image reference onto a PNG that Word can embed.

    Two sources: the plotted figures rendered from matplotlib, and the structural
    diagrams exported from draw.io. Both are looked up by file stem so the report
    does not have to care which is which.
    """
    stem = Path(ref).stem
    for folder in (DIAGRAM_PNG, PNG):
        cand = folder / f"{stem}.png"
        if cand.exists():
            return cand
    # tolerate a different export extension from draw.io
    for folder in (DIAGRAM_PNG, PNG):
        for ext in (".PNG", ".jpg", ".jpeg"):
            cand = folder / f"{stem}{ext}"
            if cand.exists():
                return cand
    return None


def _mermaid_png(caption_hint: str) -> Path | None:
    """Find the rendered PNG for a Mermaid block from its figure number."""
    m = re.search(r"Figure\s+(\d+)", caption_hint)
    if not m:
        return None
    n = int(m.group(1))
    hits = sorted(PNG.glob(f"fig{n:02d}-*.png"))
    return hits[0] if hits else None


# ------------------------------------------------------------------ main ----
def build() -> Document:
    doc = Document()

    st = doc.styles["Normal"]
    st.font.name = BODY_FONT
    st.font.size = Pt(11)
    st.paragraph_format.space_after = Pt(6)
    st.paragraph_format.line_spacing = 1.35

    for sec in doc.sections:
        sec.left_margin = sec.right_margin = Inches(1.0)
        sec.top_margin = sec.bottom_margin = Inches(1.0)

    text = SRC.read_text(encoding="utf-8")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)          # drop HTML comments
    lines = text.split("\n")

    i = 0
    pending_break = False
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        # ---- explicit page break -------------------------------------------
        if 'page-break-after' in line:
            pending_break = True
            i += 1
            continue

        # ---- fenced blocks --------------------------------------------------
        if line.startswith("```"):
            lang = line[3:].strip()
            j = i + 1
            buf = []
            while j < len(lines) and not lines[j].startswith("```"):
                buf.append(lines[j]); j += 1
            after = "\n".join(lines[j + 1: j + 6])

            if lang == "mermaid":
                img = _mermaid_png(after)
                p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                if img:
                    p.add_run().add_picture(str(img), width=Inches(MAX_IMG_IN))
                    note = doc.add_paragraph()
                    note.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    stem = img.stem.split("-")[0]
                    hits = sorted((DIAGRAMS / "drawio").glob(f"{stem}-*.drawio"))
                    where = hits[0].as_posix() if hits else "docs/diagrams/drawio/"
                    r = note.add_run(
                        f"[placeholder render — replace with the export from {where}]")
                    r.italic = True; r.font.size = Pt(8.5)
                    r.font.color.rgb = RGBColor(0x99, 0x99, 0x99)
                else:
                    _border_box(p)
                    r = p.add_run("[diagram — insert export from "
                                  "docs/diagrams/drawio/]")
                    r.italic = True
            else:
                for ln in buf:
                    p = doc.add_paragraph()
                    p.paragraph_format.space_after = Pt(0)
                    p.paragraph_format.line_spacing = 1.0
                    p.paragraph_format.left_indent = Inches(0.25)
                    _shade(p, "F5F5F5")
                    r = p.add_run(ln if ln.strip() else " ")
                    r.font.name = MONO_FONT
                    r.font.size = Pt(9)
                doc.add_paragraph().paragraph_format.space_after = Pt(4)
            i = j + 1
            continue

        # ---- tables ----------------------------------------------------------
        if (line.startswith("|") and i + 1 < len(lines)
                and re.match(r"^\|[\s:|-]+\|\s*$", lines[i + 1])):
            header = [c.strip() for c in line.strip("|").split("|")]
            j = i + 2
            rows = []
            while j < len(lines) and lines[j].startswith("|"):
                rows.append([c.strip() for c in lines[j].strip("|").split("|")])
                j += 1
            ncol = len(header)
            t = doc.add_table(rows=1, cols=ncol)
            t.style = "Light Grid Accent 1"
            t.alignment = WD_TABLE_ALIGNMENT.CENTER
            for k, h in enumerate(header):
                cell = t.rows[0].cells[k]
                cell.text = ""
                _add_runs(cell.paragraphs[0], h, base_size=9.5)
                for r in cell.paragraphs[0].runs:
                    r.bold = True
            for row in rows:
                cells = t.add_row().cells
                for k in range(ncol):
                    val = row[k] if k < len(row) else ""
                    cells[k].text = ""
                    _add_runs(cells[k].paragraphs[0], val, base_size=9.5)
            for r in t.rows:
                for c in r.cells:
                    for p in c.paragraphs:
                        p.paragraph_format.space_after = Pt(2)
                        p.paragraph_format.line_spacing = 1.0
            doc.add_paragraph().paragraph_format.space_after = Pt(4)
            i = j
            continue

        # ---- images -----------------------------------------------------------
        m = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)\s*$", line)
        if m:
            img = _image_for(m.group(2))
            p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            if img:
                p.add_run().add_picture(str(img), width=Inches(MAX_IMG_IN))
            else:
                _border_box(p)
                stem = Path(m.group(2)).stem
                r = p.add_run(
                    f"[ diagram not yet exported — save it as "
                    f"docs/img/diagrams/{stem}.png, then re-run "
                    f"python -m tools.make_docx ]")
                r.italic = True
                r.font.size = Pt(9.5)
                r.font.color.rgb = RGBColor(0xB0, 0x30, 0x30)
            i += 1
            continue

        # ---- headings ---------------------------------------------------------
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level, title = len(m.group(1)), m.group(2).strip()
            chapter = bool(re.match(r"^(CHAPTER|Front Matter)", title, re.I))
            if pending_break or (chapter and doc.paragraphs):
                doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
                pending_break = False
            h = doc.add_heading(level=min(level, 4))
            _add_runs(h, title, base_size=16 - 1.6 * min(level, 4))
            for r in h.runs:
                r.font.name = BODY_FONT
                r.font.color.rgb = RGBColor(0x1A, 0x1A, 0x1A)
            h.paragraph_format.space_before = Pt(12 if level <= 2 else 8)
            h.paragraph_format.space_after = Pt(5)
            i += 1
            continue

        # ---- block quote ------------------------------------------------------
        if line.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i].lstrip("> ").rstrip()); i += 1
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.4)
            p.paragraph_format.right_indent = Inches(0.3)
            _shade(p, "FBF7E8")
            _add_runs(p, " ".join(buf))
            for r in p.runs:
                r.italic = True
            continue

        # ---- lists ------------------------------------------------------------
        m = re.match(r"^(\s*)([-*])\s+(.*)$", raw)
        if m:
            depth = len(m.group(1)) // 2
            p = doc.add_paragraph(style="List Bullet" if depth == 0 else "List Bullet 2")
            _add_runs(p, m.group(3))
            i += 1
            continue
        m = re.match(r"^(\s*)(\d+)\.\s+(.*)$", raw)
        if m:
            depth = len(m.group(1)) // 2
            p = doc.add_paragraph(style="List Number" if depth == 0 else "List Number 2")
            _add_runs(p, m.group(3))
            i += 1
            continue

        # ---- horizontal rule ---------------------------------------------------
        if re.match(r"^-{3,}\s*$", line):
            i += 1
            continue

        # ---- blank -------------------------------------------------------------
        if not line.strip():
            i += 1
            continue

        # ---- paragraph (join the hard-wrapped lines) ---------------------------
        buf = [line]
        j = i + 1
        while (j < len(lines) and lines[j].strip()
               and not re.match(r"^(#{1,6}\s|\||```|>|\s*[-*]\s|\s*\d+\.\s|!\[)", lines[j])
               and "page-break-after" not in lines[j]):
            buf.append(lines[j].rstrip()); j += 1
        body = " ".join(buf)

        p = doc.add_paragraph()
        cap = re.match(r"^\*\*(Figure|Table)\s+\d+", body)
        if cap:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(12)
            _add_runs(p, body, base_size=9.5)
            for r in p.runs:
                r.font.size = Pt(9.5)
        else:
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            _add_runs(p, body)
        i = j
        continue

    return doc


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"{SRC} not found -- run `python -m tools.build_report` first")
    doc = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)

    n_par = len(doc.paragraphs)
    n_tab = len(doc.tables)
    n_img = sum(1 for s in doc.inline_shapes)
    size = OUT.stat().st_size / 1024
    print(f"  wrote {OUT}  ({size:,.0f} KB)")
    print(f"  {n_par:,} paragraphs | {n_tab} tables | {n_img} images")


if __name__ == "__main__":
    main()
