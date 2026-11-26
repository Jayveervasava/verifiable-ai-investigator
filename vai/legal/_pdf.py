"""Small reportlab toolkit shared by the case report and the Section 63 draft."""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

NAVY = colors.HexColor("#1F3A5F")
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#EEF2F7")
GREEN = colors.HexColor("#DFF3E3")
AMBER = colors.HexColor("#FFF1CC")
RED = colors.HexColor("#F9D6D5")


def safe(text) -> str:
    """Built-in PDF fonts only know Western characters; replace anything else with '?'."""
    return str("" if text is None else text).encode("cp1252", errors="replace").decode("cp1252")


def esc(text) -> str:
    return escape(safe(text))


def mm_(*widths: float) -> list[float]:
    return [w * mm for w in widths]


STYLES = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceAfter=4),
    "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=10, leading=13, textColor=GREY, spaceAfter=6),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=NAVY, spaceBefore=10, spaceAfter=4),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=6, spaceAfter=2),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12, spaceAfter=3),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9, leading=12, leftIndent=10, bulletIndent=0, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.5, leading=9.5, wordWrap="CJK"),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, wordWrap="CJK"),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7, leading=8.6, wordWrap="CJK"),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=GREY),
}


def P(text, style="body") -> Paragraph:
    """Paragraph from plain text (escaped)."""
    return Paragraph(esc(text), STYLES[style])


def PR(markup, style="body") -> Paragraph:
    """Paragraph from markup the caller has already escaped (use esc() on data)."""
    return Paragraph(markup, STYLES[style])


def bullet(text) -> Paragraph:
    return Paragraph(esc(text), STYLES["bullet"], bulletText="-")


def banner(text, kind="amber") -> Table:
    bg = {"green": GREEN, "amber": AMBER, "red": RED, "grey": LIGHT}[kind]
    t = Table([[PR(f"<b>{esc(text)}</b>", "body")]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.6, GREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def kv_table(rows, widths=(45, 129)) -> Table:
    data = [[P(k, "cellb"), v if hasattr(v, "wrap") else P(v, "cell")] for k, v in rows]
    t = Table(data, colWidths=mm_(*widths))
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def grid_table(header, rows, widths) -> Table:
    data = [[P(h, "cellb") for h in header]]
    for r in rows:
        data.append([c if hasattr(c, "wrap") else P(c, "cell") for c in r])
    t = Table(data, colWidths=mm_(*widths), repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def mono(text) -> Paragraph:
    return Paragraph(esc(text), STYLES["mono"])


def _canvas_class(watermark: str | None, footer: str):
    class _Canvas(canvas.Canvas):
        """Two-pass canvas: draws watermark, footer and 'Page x of y' on every page."""

        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            if watermark:
                self.saveState()
                self.setFillColor(colors.Color(0.5, 0.5, 0.5))
                self.setFillAlpha(0.16)
                self.setFont("Helvetica-Bold", 38)
                self.translate(PAGE_W / 2, PAGE_H / 2)
                self.rotate(45)
                self.drawCentredString(0, 0, watermark)
                self.restoreState()
            self.saveState()
            self.setFont("Helvetica", 7)
            self.setFillColor(GREY)
            self.drawString(MARGIN, 10 * mm, safe(footer))
            self.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return _Canvas


def build_pdf(story, *, title: str, author: str, subject: str, watermark: str | None, footer: str) -> bytes:
    """Build the PDF. `invariant=1` makes the bytes identical for identical input."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=16 * mm, bottomMargin=18 * mm,
        title=safe(title), author=safe(author), subject=safe(subject), invariant=1,
    )
    doc.build(story, canvasmaker=_canvas_class(watermark, footer))
    return buf.getvalue()
