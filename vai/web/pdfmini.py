"""Tiny dependency-free PDF writer (plain text, A4, Helvetica). Used by the mock legal module."""
from __future__ import annotations

import textwrap

_REPL = {"\u2013": "-", "\u2014": "-", "\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
         "\u2192": "->", "\u2022": "*", "\u00b7": "-", "\u2026": "..."}


def _clean(s: str) -> str:
    for k, v in _REPL.items():
        s = s.replace(k, v)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines: list[str]) -> bytes:
    """Lines starting with '# ' are bold headings. Long lines are wrapped."""
    rows: list[tuple[str, str]] = []
    for ln in lines:
        if ln.startswith("# "):
            rows.append(("F2", ln[2:]))
        elif ln == "":
            rows.append(("F1", ""))
        else:
            for w in textwrap.wrap(ln, 92) or [""]:
                rows.append(("F1", w))
    per_page = 52
    pages = [rows[i:i + per_page] for i in range(0, len(rows), per_page)] or [[]]

    objs: list[bytes] = []

    def add(b: bytes) -> int:
        objs.append(b)
        return len(objs)

    add(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1
    add(b"")  # 2 placeholder (Pages)
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # 3
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")  # 4
    kids = []
    for pg in pages:
        parts = ["BT", "50 800 Td", "14 TL"]
        for font, text in pg:
            size = 12 if font == "F2" else 10
            parts.append(f"/{font} {size} Tf")
            parts.append(f"({_clean(text)}) '")
        parts.append("ET")
        stream = "\n".join(parts).encode("latin-1")
        cid = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        pid = add(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents {cid} 0 R "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>".encode()
        )
        kids.append(pid)
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)
