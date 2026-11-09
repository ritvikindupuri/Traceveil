#!/usr/bin/env python3
"""Generate the Traceveil architecture diagram from measured layout.

Layout is original to Traceveil: one left-to-right investigation run, a
GitHub/live collection fork, and a dashed MCP lane. Style references are
color and type quality only — do not copy their structure.

Official product marks (GitHub, Gemini, Cloudflare, Microsoft) are vendored
from Simple Icons. AI agents use a generic robot glyph, not a vendor logo.

Run from the repo root:

    python3 docs/architecture/generate.py

Needs Pillow and CairoSVG. Writes SVG + PNG and exits non-zero if text, icons,
or arrows intersect, if text overflows its box, or if anything is clipped.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image, ImageFont

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
ICONS = ROOT / "icons"
OUT_SVG = ROOT / "traceveil-architecture.svg"
OUT_PNG = ROOT / "traceveil-architecture.png"
OUT_PNG_838 = ROOT / "traceveil-architecture-838.png"

W, H = 1800, 900
MARGIN = 16
TEXT_GAP = 16
ARROW_CLEAR = 10
STROKE = 1.75

FONT_REG_PATH = "/usr/share/fonts/truetype/macos/Inter-Regular.ttf"
FONT_MED_PATH = "/usr/share/fonts/truetype/macos/Inter-Medium.ttf"
FONT_SEM_PATH = "/usr/share/fonts/truetype/macos/Inter-SemiBold.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/macos/Inter-Bold.ttf"

# Ink colors chosen to match the shipped diagrams' quality, not their layout.
INK = "#0F172A"
MUTED = "#64748B"
LINE = "#94A3B8"
LINE_STRONG = "#64748B"
CARD = "#FFFFFF"
CARD_BORDER = "#E2E8F0"
REGION = "#F8FAFC"
REGION_BORDER = "#CBD5E1"
BADGE = "#EA580C"
BADGE_TEXT = "#FFFFFF"
CALLOUT_BG = "#FFF7ED"
CALLOUT_BORDER = "#FDBA74"
DASH = "6 5"

# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------


@dataclass
class Rect:
    x: float
    y: float
    w: float
    h: float
    kind: str
    name: str
    parent: str | None = None
    ignore_vs: frozenset[str] = field(default_factory=frozenset)

    @property
    def r(self) -> float:
        return self.x + self.w

    @property
    def b(self) -> float:
        return self.y + self.h

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    def inflate(self, p: float) -> "Rect":
        return Rect(self.x - p, self.y - p, self.w + 2 * p, self.h + 2 * p, self.kind, self.name, self.parent)


@dataclass
class Seg:
    x1: float
    y1: float
    x2: float
    y2: float
    name: str


def fonts(size: int, weight: str = "regular") -> ImageFont.FreeTypeFont:
    path = {
        "regular": FONT_REG_PATH,
        "medium": FONT_MED_PATH,
        "semibold": FONT_SEM_PATH,
        "bold": FONT_BOLD_PATH,
    }[weight]
    return ImageFont.truetype(path, size)


def measure(text: str, size: int, weight: str = "regular") -> tuple[float, float, float]:
    """Return (width, height, ascent) for SVG baseline placement."""
    font = fonts(size, weight)
    ascent, descent = font.getmetrics()
    width = float(font.getlength(text))
    return width, float(ascent + descent), float(ascent)


def parse_icon_path(name: str) -> str:
    raw = (ICONS / name).read_text()
    match = re.search(r'<path d="([^"]+)"', raw)
    if not match:
        raise SystemExit(f"no path in {name}")
    return match.group(1)


GITHUB_PATH = parse_icon_path("github.svg")
GEMINI_PATH = parse_icon_path("googlegemini.svg")
CLOUDFLARE_PATH = parse_icon_path("cloudflare.svg")
MICROSOFT_PATH = parse_icon_path("microsoft.svg")

# Generic 24x24 icons (Heroicons-style outlines, drawn filled for this diagram).
USER_PATH = (
    "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm0 2c-4.4 0-8 2.1-8 4.7V21h16v-2.3C20 16.1 16.4 14 12 14z"
)
ROBOT_PATHS = [
    "M12 2.5a1 1 0 0 1 1 1V5h3.5A2.5 2.5 0 0 1 19 7.5v8A2.5 2.5 0 0 1 16.5 18h-9A2.5 2.5 0 0 1 5 15.5v-8A2.5 2.5 0 0 1 7.5 5H11V3.5a1 1 0 0 1 1-1z",
    "M9 10.5a1.25 1.25 0 1 0 0-2.5 1.25 1.25 0 0 0 0 2.5zm6 0a1.25 1.25 0 1 0 0-2.5 1.25 1.25 0 0 0 0 2.5z",
    "M9.5 14h5a.75.75 0 0 1 0 1.5h-5A.75.75 0 0 1 9.5 14z",
    "M8 18.5v1.2A2.3 2.3 0 0 0 10.3 22h3.4A2.3 2.3 0 0 0 16 19.7v-1.2",
]
FILE_PATH = (
    "M7 3.5h6.2L17 7.3V20a1.5 1.5 0 0 1-1.5 1.5h-8A1.5 1.5 0 0 1 6 20V5A1.5 1.5 0 0 1 7.5 3.5H7zm6 0v4h4"
)
GLOBE_PATHS = [
    "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z",
    "M3 12h18",
    "M12 3c2.4 2.4 3.6 5.6 3.6 9s-1.2 6.6-3.6 9c-2.4-2.4-3.6-5.6-3.6-9S9.6 5.4 12 3z",
]
LOCK_PATH = (
    "M8 10V7.8A4 4 0 0 1 12 4a4 4 0 0 1 4 3.8V10h1.5A1.5 1.5 0 0 1 19 11.5v7A1.5 1.5 0 0 1 17.5 20h-11A1.5 1.5 0 0 1 5 18.5v-7A1.5 1.5 0 0 1 6.5 10H8zm1.5 0h5V7.8A2.5 2.5 0 0 0 12 5.5 2.5 2.5 0 0 0 9.5 7.8V10z"
)
SHIELD_PATH = (
    "M12 3.2 19 6v6.2c0 4.2-2.8 7.2-7 8.6-4.2-1.4-7-4.4-7-8.6V6l7-2.8z"
)
WINDOW_PATHS = [
    "M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v11A2.5 2.5 0 0 1 17.5 20h-11A2.5 2.5 0 0 1 4 17.5v-11z",
    "M4 8.5h16",
    "M7 6.4h.01M9.2 6.4h.01M11.4 6.4h.01",
]


# ---------------------------------------------------------------------------
# Scene
# ---------------------------------------------------------------------------


class Scene:
    def __init__(self) -> None:
        self.svg: list[str] = []
        self.rects: list[Rect] = []
        self.segs: list[Seg] = []
        self._z = 0

    def add_rect(self, rect: Rect) -> Rect:
        self.rects.append(rect)
        return rect

    def text_box(
        self,
        x: float,
        y: float,
        text: str,
        size: int,
        weight: str,
        fill: str,
        anchor: str = "start",
        name: str = "",
        parent: str | None = None,
        extra: str = "",
    ) -> Rect:
        tw, th, ascent = measure(text, size, weight)
        if anchor == "middle":
            tx = x
            box_x = x - tw / 2
        elif anchor == "end":
            tx = x
            box_x = x - tw
        else:
            tx = x
            box_x = x
        # SVG y is baseline; box covers ink.
        box = Rect(box_x, y - ascent, tw, th, "text", name or f"text:{text}", parent)
        self.add_rect(box)
        anchor_attr = f'text-anchor="{anchor}"' if anchor != "start" else ""
        self.svg.append(
            f'<text x="{tx:.2f}" y="{y:.2f}" font-size="{size}" font-weight="{weight_css(weight)}" '
            f'fill="{fill}" {anchor_attr} {extra}>{escape(text)}</text>'
        )
        return box

    def round_rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        rx: float,
        fill: str,
        stroke: str,
        sw: float = 1.2,
        dash: str | None = None,
        name: str = "",
        kind: str = "shape",
    ) -> Rect:
        dash_attr = f'stroke-dasharray="{dash}"' if dash else ""
        self.svg.append(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}" {dash_attr}/>'
        )
        return self.add_rect(Rect(x, y, w, h, kind, name or "rect"))

    def icon_badge(
        self,
        cx: float,
        cy: float,
        r: float,
        bg: str,
        paths: list[tuple[str, str, str]],
        name: str,
        parent: str,
        scale: float = 0.92,
    ) -> Rect:
        """paths: list of (d, fill, extra_attrs) in 24x24 space."""
        self.svg.append(f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{bg}"/>')
        box = self.add_rect(Rect(cx - r, cy - r, 2 * r, 2 * r, "icon", name, parent))
        s = (r * scale * 2) / 24
        ox = cx - 12 * s
        oy = cy - 12 * s
        self.svg.append(f'<g transform="translate({ox:.2f} {oy:.2f}) scale({s:.4f})">')
        for d, fill, extra in paths:
            fill_attr = "" if "fill=" in extra else f'fill="{fill}"'
            self.svg.append(f'<path d="{d}" {fill_attr} {extra}/>')
        self.svg.append("</g>")
        return box

    def node_card(
        self,
        x: float,
        y: float,
        title: str,
        subtitle: str,
        icon: list[tuple[str, str, str]],
        icon_bg: str,
        name: str,
        dashed: bool = False,
        min_w: float = 168,
    ) -> Rect:
        title_w, title_h, title_ascent = measure(title, 16, "bold")
        sub_w, sub_h, sub_ascent = measure(subtitle, 12, "regular")
        pad_x, pad_y = 14, 12
        icon_r = 19
        gap = 10
        inner_w = max(min_w - 2 * pad_x, title_w, sub_w, icon_r * 2)
        w = inner_w + 2 * pad_x
        # icon, 8px, title, 4px, subtitle
        h = pad_y + icon_r * 2 + 8 + title_h + 4 + sub_h + pad_y
        dash = DASH if dashed else None
        fill = "#FCFCFD" if dashed else CARD
        stroke = "#94A3B8" if dashed else CARD_BORDER
        card = self.round_rect(x, y, w, h, 14, fill, stroke, 1.3, dash, name, "node")
        cx = x + w / 2
        icon_cy = y + pad_y + icon_r
        self.icon_badge(cx, icon_cy, icon_r, icon_bg, icon, f"{name}:icon", name)
        title_y = icon_cy + icon_r + 8 + title_ascent
        self.text_box(cx, title_y, title, 16, "bold", INK, "middle", f"{name}:title", name)
        sub_y = title_y + (title_h - title_ascent) + 4 + sub_ascent
        self.text_box(cx, sub_y, subtitle, 12, "regular", MUTED, "middle", f"{name}:sub", name)
        # Ensure computed height really contains text (defensive).
        last = [r for r in self.rects if r.parent == name and r.kind == "text"][-1]
        if last.b + pad_y - y > h + 0.5:
            raise SystemExit(f"node {name} height too small for text")
        return card

    def callout(self, x: float, y: float, number: int, text: str, name: str) -> Rect:
        """Badge + label. (x,y) is the top-left of the combined group."""
        tw, th, ascent = measure(text, 12, "medium")
        badge_r = 9
        pad_x, pad_y = 10, 6
        gap = 8
        box_w = pad_x + tw + pad_x
        box_h = pad_y + th + pad_y
        # Badge sits on the left, vertically centered with the label box.
        group_h = max(badge_r * 2, box_h)
        badge_cx = x + badge_r
        badge_cy = y + group_h / 2
        box_x = badge_cx + badge_r + gap
        box_y = y + (group_h - box_h) / 2
        group = self.add_rect(Rect(x, y, box_x + box_w - x, group_h, "callout", name))
        self.svg.append(
            f'<rect x="{box_x:.2f}" y="{box_y:.2f}" width="{box_w:.2f}" height="{box_h:.2f}" '
            f'rx="8" fill="{CALLOUT_BG}" stroke="{CALLOUT_BORDER}" stroke-width="1"/>'
        )
        self.add_rect(Rect(box_x, box_y, box_w, box_h, "callout-box", f"{name}:box", name))
        self.svg.append(
            f'<circle cx="{badge_cx:.2f}" cy="{badge_cy:.2f}" r="{badge_r:.2f}" fill="{BADGE}"/>'
        )
        self.add_rect(
            Rect(badge_cx - badge_r, badge_cy - badge_r, badge_r * 2, badge_r * 2, "icon", f"{name}:badge", name)
        )
        num = str(number)
        nw, nh, nas = measure(num, 10, "bold")
        self.text_box(badge_cx, badge_cy - nh / 2 + nas, num, 10, "bold", BADGE_TEXT, "middle", f"{name}:num", name)
        self.text_box(
            box_x + pad_x,
            box_y + pad_y + ascent,
            text,
            12,
            "medium",
            "#9A3412",
            "start",
            f"{name}:label",
            name,
        )
        return group

    def region(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        label: str,
        name: str,
        dashed: bool = False,
    ) -> Rect:
        dash = DASH if dashed else None
        fill = "#F8FAFC" if not dashed else "#FAFBFC"
        stroke = "#94A3B8" if dashed else REGION_BORDER
        self.round_rect(x, y, w, h, 18, fill, stroke, 1.4, dash, name, "region")
        self.text_box(x + 16, y + 22, label, 11, "semibold", MUTED, "start", f"{name}:label", name)
        return self.rects[-2]

    def arrow(self, points: list[tuple[float, float]], name: str, dashed: bool = False) -> None:
        if len(points) < 2:
            raise SystemExit(f"arrow {name} needs 2+ points")
        d = f"M {points[0][0]:.2f} {points[0][1]:.2f}"
        for x, y in points[1:]:
            d += f" L {x:.2f} {y:.2f}"
        dash_attr = f'stroke-dasharray="{DASH}"' if dashed else ""
        marker = "url(#arrow-dash)" if dashed else "url(#arrow)"
        self.svg.append(
            f'<path d="{d}" fill="none" stroke="{LINE_STRONG}" stroke-width="{STROKE}" '
            f'stroke-linejoin="round" stroke-linecap="round" marker-end="{marker}" {dash_attr}/>'
        )
        for i in range(len(points) - 1):
            self.segs.append(Seg(points[i][0], points[i][1], points[i + 1][0], points[i + 1][1], name))
            # Keep a rect around each segment for coarse tests.
            x1, y1 = points[i]
            x2, y2 = points[i + 1]
            pad = STROKE / 2
            self.add_rect(
                Rect(
                    min(x1, x2) - pad,
                    min(y1, y2) - pad,
                    abs(x2 - x1) + STROKE,
                    abs(y2 - y1) + STROKE,
                    "arrow",
                    f"{name}:{i}",
                )
            )

    def host_chip(
        self,
        x: float,
        y: float,
        title: str,
        icon: list[tuple[str, str, str]],
        icon_bg: str,
        name: str,
    ) -> Rect:
        tw, th, ascent = measure(title, 11, "semibold")
        pad_x, pad_y = 10, 8
        icon_r = 12
        w = pad_x + icon_r * 2 + 8 + tw + pad_x
        h = pad_y + max(icon_r * 2, th) + pad_y
        card = self.round_rect(x, y, w, h, 10, CARD, CARD_BORDER, 1.1, None, name, "node")
        self.icon_badge(x + pad_x + icon_r, y + h / 2, icon_r, icon_bg, icon, f"{name}:icon", name, 0.88)
        self.text_box(
            x + pad_x + icon_r * 2 + 8,
            y + (h - th) / 2 + ascent,
            title,
            11,
            "semibold",
            INK,
            "start",
            f"{name}:title",
            name,
        )
        return card


def weight_css(weight: str) -> str:
    return {"regular": "400", "medium": "500", "semibold": "600", "bold": "700"}[weight]


def node_anchor(rect: Rect, side: str, inset: float = 0) -> tuple[float, float]:
    gap = ARROW_CLEAR + inset
    if side == "left":
        return rect.x - gap, rect.cy
    if side == "right":
        return rect.r + gap, rect.cy
    if side == "top":
        return rect.cx, rect.y - gap
    if side == "bottom":
        return rect.cx, rect.b + gap
    raise ValueError(side)


def hline(a: Rect, b: Rect, y: float | None = None) -> list[tuple[float, float]]:
    y = a.cy if y is None else y
    return [(a.r + ARROW_CLEAR, y), (b.x - ARROW_CLEAR, y)]


# ---------------------------------------------------------------------------
# Layout — original investigation run (LTR + collection fork + MCP lane)
# ---------------------------------------------------------------------------


def build() -> Scene:
    s = Scene()
    s.svg.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        f'role="img" aria-labelledby="title desc">'
    )
    s.svg.append("<defs>")
    s.svg.append(
        '<marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        f'<path d="M0,0.6 L7.2,4 L0,7.4" fill="{LINE_STRONG}"/>'
        "</marker>"
    )
    s.svg.append(
        '<marker id="arrow-dash" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        f'<path d="M0,0.6 L7.2,4 L0,7.4" fill="{LINE_STRONG}"/>'
        "</marker>"
    )
    s.svg.append(
        "<style>"
        "svg { font-family: Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; }"
        "text { paint-order: stroke; stroke: none; }"
        "</style>"
    )
    s.svg.append("</defs>")
    s.round_rect(0, 0, W, H, 0, "#FFFFFF", "#FFFFFF", 0, None, "canvas", "canvas")
    s.rects[-1].ignore_vs = frozenset({"*"})

    s.text_box(W / 2, 32, "How a Traceveil investigation run works", 22, "bold", INK, "middle", "title")
    s.text_box(
        W / 2,
        54,
        "One signed-in scan: collect evidence, save an owner-scoped record, then inspect the graph.",
        12,
        "regular",
        MUTED,
        "middle",
        "subtitle",
    )

    user_icon = [(USER_PATH, "#FFFFFF", "")]
    window_icon = [
        (f'{WINDOW_PATHS[0]} M5.4 4.7h13.2v2.6H5.4z', "#FFFFFF", 'fill-rule="evenodd"'),
    ]
    scan_icon = [(SHIELD_PATH, "#FFFFFF", "")]
    github_icon = [(GITHUB_PATH, "#181717", "")]
    globe_icon = [
        (GLOBE_PATHS[0], "none", 'fill="none" stroke="#FFFFFF" stroke-width="1.8"'),
        (GLOBE_PATHS[1], "none", 'fill="none" stroke="#FFFFFF" stroke-width="1.8"'),
        (GLOBE_PATHS[2], "none", 'fill="none" stroke="#FFFFFF" stroke-width="1.8"'),
    ]
    file_icon = [(FILE_PATH, "#FFFFFF", "")]
    robot_icon = [
        (" ".join(ROBOT_PATHS[:3]), "#FFFFFF", 'fill-rule="evenodd"'),
        (ROBOT_PATHS[3], "#FFFFFF", ""),
    ]
    lock_icon = [(LOCK_PATH, "#FFFFFF", "")]
    gemini_icon = [(GEMINI_PATH, "#8E75FF", "")]
    cf_icon = [(CLOUDFLARE_PATH, "#F38020", "")]
    ms_icon = [(MICROSOFT_PATH, "#0078D4", "")]
    wiki_icon = [(FILE_PATH, "#0F172A", "")]

    # Regions first (under nodes). Top padding leaves a strip for in-region callouts.
    s.region(20, 118, 318, 652, "Browser", "region-browser")
    s.region(352, 118, 1012, 652, "Traceveil server  ·  Node process, no repository code executed", "region-server")
    s.region(1378, 118, 400, 420, "Browser", "region-results")
    s.region(1378, 548, 400, 222, "Allowlisted MCP hosts  ·  runtime only", "region-mcp", dashed=True)

    you = s.node_card(90, 205, "You", "Signed-in investigator", user_icon, "#334155", "you")
    console = s.node_card(74, 360, "Console", "Workspace after sign-in", window_icon, "#4F46E5", "console")
    mcp_page = s.node_card(74, 640, "MCP audits", "/mcp-audits page", window_icon, "#9A3412", "mcp-page", True)

    scan = s.node_card(376, 236, "Scan API", "POST /api/application-scan", scan_icon, "#0284C7", "scan")
    github = s.node_card(628, 160, "GitHub collector", "Bounded public snapshot", github_icon, "#E2E8F0", "github")
    pat_title = "Encrypted GitHub PAT"
    pat_tw, _, _ = measure(pat_title, 11, "semibold")
    pat_w = 10 + 24 + 8 + pat_tw + 10
    pat = s.host_chip(github.x + (github.w - pat_w) / 2, github.b + 24, pat_title, lock_icon, "#334155", "pat")
    s.svg.append(
        f'<rect x="{pat.x:.2f}" y="{pat.y:.2f}" width="{pat.w:.2f}" height="{pat.h:.2f}" '
        f'rx="10" fill="none" stroke="#94A3B8" stroke-width="1.3" stroke-dasharray="{DASH}"/>'
    )
    live = s.node_card(628, 360, "Live HTTPS probes", "Four GETs on port 443", globe_icon, "#0F766E", "live")
    graph = s.node_card(900, 236, "Graph engine", "Static rules, evidence IDs", scan_icon, "#7C3AED", "graph")
    agents = s.node_card(1148, 236, "Report agents", "Four template write-ups", robot_icon, "#0F766E", "agents")
    store = s.node_card(900, 500, "Local JSON store", "Owner-readable scan record", file_icon, "#D97706", "store")
    guard = s.node_card(1148, 500, "Tool guard", "POST /api/guard checks", lock_icon, "#BE123C", "guard", True)
    mcp_scan = s.node_card(376, 640, "MCP ingest", "POST /api/scan NDJSON", scan_icon, "#C2410C", "mcp-scan", True)

    canvas = s.node_card(1488, 205, "Results canvas", "React Flow + Dagre layout", window_icon, "#4338CA", "canvas-node")
    isolation = s.node_card(1472, 360, "Isolation agent", "Chat drafts RLS text", robot_icon, "#5B21B6", "isolation", True)
    gemini = s.host_chip(1488, 486, "Google Gemini", gemini_icon, "#EDE9FE", "gemini")
    s.svg.append(
        f'<rect x="{gemini.x:.2f}" y="{gemini.y:.2f}" width="{gemini.w:.2f}" height="{gemini.h:.2f}" '
        f'rx="10" fill="none" stroke="#94A3B8" stroke-width="1.3" stroke-dasharray="{DASH}"/>'
    )

    deepwiki = s.host_chip(1410, 586, "DeepWiki", wiki_icon, "#E2E8F0", "deepwiki")
    cloudflare = s.host_chip(1410, 638, "Cloudflare Docs", cf_icon, "#FFF7ED", "cloudflare")
    microsoft = s.host_chip(1410, 690, "Microsoft Learn", ms_icon, "#EFF6FF", "microsoft")

    # --- Solid path: You → Console → Scan → (GitHub | Live) → Graph → Agents → Canvas
    #                                      ↘ Store
    s.arrow([node_anchor(you, "bottom"), node_anchor(console, "top")], "a1")

    rail = scan.x - 36
    s.arrow(
        [
            (console.r + ARROW_CLEAR, console.cy),
            (rail, console.cy),
            (rail, scan.cy),
            (scan.x - ARROW_CLEAR, scan.cy),
        ],
        "a2",
    )

    fork_x = (scan.r + github.x) / 2
    s.arrow(
        [
            (scan.r + ARROW_CLEAR, scan.cy),
            (fork_x, scan.cy),
            (fork_x, github.cy),
            (github.x - ARROW_CLEAR, github.cy),
        ],
        "a3-gh",
    )
    s.arrow(
        [
            (fork_x, scan.cy),
            (fork_x, live.cy),
            (live.x - ARROW_CLEAR, live.cy),
        ],
        "a3-live",
    )

    join_x = (max(github.r, live.r) + graph.x) / 2
    s.arrow(
        [
            (github.r + ARROW_CLEAR, github.cy),
            (join_x, github.cy),
            (join_x, graph.cy),
            (graph.x - ARROW_CLEAR, graph.cy),
        ],
        "a4-gh",
    )
    s.arrow(
        [
            (live.r + ARROW_CLEAR, live.cy),
            (join_x, live.cy),
            (join_x, graph.cy),
        ],
        "a4-live",
    )

    s.arrow([node_anchor(graph, "bottom"), node_anchor(store, "top")], "a5")
    s.arrow([(graph.r + ARROW_CLEAR, graph.cy), (agents.x - ARROW_CLEAR, agents.cy)], "a6")

    out_x = agents.r + 28
    s.arrow(
        [
            (agents.r + ARROW_CLEAR, agents.cy),
            (out_x, agents.cy),
            (out_x, canvas.cy),
            (canvas.x - ARROW_CLEAR, canvas.cy),
        ],
        "a7",
    )

    # Dashed PAT hangs off the GitHub collector (loaded at collect time).
    s.arrow(
        [
            (github.cx, github.b + ARROW_CLEAR),
            (github.cx, pat.y - ARROW_CLEAR),
        ],
        "d-pat",
        True,
    )

    # Dashed MCP: Console → audits → ingest → Store (rejoin) and Guard → hosts.
    s.arrow([node_anchor(console, "bottom"), node_anchor(mcp_page, "top")], "d-mcp-1", True)
    s.arrow(
        [(mcp_page.r + ARROW_CLEAR, mcp_page.cy), (mcp_scan.x - ARROW_CLEAR, mcp_scan.cy)],
        "d-mcp-2",
        True,
    )
    stem = mcp_scan.r + 40
    s.arrow(
        [
            (mcp_scan.r + ARROW_CLEAR, mcp_scan.cy),
            (stem, mcp_scan.cy),
            (stem, store.cy),
            (store.x - ARROW_CLEAR, store.cy),
        ],
        "d-mcp-store",
        True,
    )
    s.arrow(
        [
            (stem, mcp_scan.cy),
            (guard.cx, mcp_scan.cy),
            (guard.cx, guard.b + ARROW_CLEAR),
        ],
        "d-mcp-guard",
        True,
    )
    s.arrow(
        [
            (guard.r + ARROW_CLEAR, guard.cy),
            (1370, guard.cy),
            (1370, deepwiki.cy),
            (deepwiki.x - ARROW_CLEAR, deepwiki.cy),
        ],
        "d-guard-hosts",
        True,
    )

    s.arrow(
        [
            (agents.cx, agents.b + ARROW_CLEAR),
            (agents.cx, isolation.cy),
            (isolation.x - ARROW_CLEAR, isolation.cy),
        ],
        "d-iso",
        True,
    )
    s.arrow(
        [node_anchor(isolation, "bottom"), node_anchor(gemini, "top")],
        "d-gemini",
        True,
    )

    # Callouts sit beside the arrows they explain — never on the stroke.
    s.callout(90, 159, 1, "Sign in; session stays here", "c1")
    s.callout(258, 428, 2, "Pick repo or live app", "c2")
    s.callout(376, 190, 3, "Authenticated scan starts", "c3")
    s.callout(628, 486, 4, "GitHub files or live HTTPS", "c4")
    s.callout(900, 190, 5, "Static rules bind evidence", "c5")
    s.callout(1148, 190, 6, "Record saved; agents report", "c6")
    s.callout(1488, 159, 7, "Canvas draws the graph", "c7")
    s.callout(610, 612, 8, "Optional MCP audit and guard", "c8")

    s.text_box(
        24,
        884,
        "Dashed = optional or config-dependent (GitHub PAT, Gemini API key, MCP audit, tool guard). Numbered callouts 1–8 match the README steps.",
        11,
        "regular",
        MUTED,
        "start",
        "legend",
    )

    s.svg.append("</svg>")
    return s


# ---------------------------------------------------------------------------
# Collision checks
# ---------------------------------------------------------------------------


def rects_overlap(a: Rect, b: Rect, gap: float = 0) -> bool:
    return not (a.r + gap <= b.x or b.r + gap <= a.x or a.b + gap <= b.y or b.b + gap <= a.y)


def seg_intersects_rect(seg: Seg, rect: Rect, clearance: float) -> bool:
    # Axis-aligned segments only (this diagram uses orthogonal arrows).
    pad = clearance
    rx, ry, rw, rh = rect.x - pad, rect.y - pad, rect.w + 2 * pad, rect.h + 2 * pad
    x1, y1, x2, y2 = seg.x1, seg.y1, seg.x2, seg.y2
    if abs(y1 - y2) < 0.01:
        y = y1
        xlo, xhi = min(x1, x2), max(x1, x2)
        return ry <= y <= ry + rh and xlo <= rx + rw and xhi >= rx
    if abs(x1 - x2) < 0.01:
        x = x1
        ylo, yhi = min(y1, y2), max(y1, y2)
        return rx <= x <= rx + rw and ylo <= ry + rh and yhi >= ry
    # Fallback for non-ortho (should not happen).
    return False


def parent_box(scene: Scene, name: str) -> Rect | None:
    for r in scene.rects:
        if r.name == name and r.kind in {"node", "callout", "callout-box", "region"}:
            return r
    return None


def check(scene: Scene) -> list[str]:
    errors: list[str] = []
    texts = [r for r in scene.rects if r.kind == "text"]
    icons = [r for r in scene.rects if r.kind == "icon"]
    nodes = [r for r in scene.rects if r.kind == "node"]
    callouts = [r for r in scene.rects if r.kind == "callout"]
    arrows = [r for r in scene.rects if r.kind == "arrow"]

    canvas = Rect(MARGIN, MARGIN, W - 2 * MARGIN, H - 2 * MARGIN, "canvas", "safe")

    def in_canvas(r: Rect) -> bool:
        return r.x >= canvas.x - 0.5 and r.y >= canvas.y - 0.5 and r.r <= canvas.r + 0.5 and r.b <= canvas.b + 0.5

    for r in texts + icons + nodes + callouts:
        if r.name in {"title", "subtitle", "legend"} or (r.parent in {None, "title", "subtitle", "legend"} and r.kind == "text"):
            if not (r.x >= 8 and r.r <= W - 8 and r.y >= 8 and r.b <= H - 8):
                errors.append(f"clipped {r.name} ({r.x:.1f},{r.y:.1f} {r.w:.1f}x{r.h:.1f})")
            continue
        if not in_canvas(r):
            errors.append(f"clipped {r.name} ({r.x:.1f},{r.y:.1f} {r.w:.1f}x{r.h:.1f})")

    # Text must stay inside its parent box.
    for t in texts:
        if not t.parent:
            continue
        parent = next((r for r in scene.rects if r.name == t.parent and r.kind in {"node", "callout", "callout-box", "region"}), None)
        if parent is None:
            # try callout-box specifically
            parent = next((r for r in scene.rects if r.name == f"{t.parent}:box"), None)
        if parent is None:
            continue
        pad = 4 if parent.kind == "region" else 6
        if t.x < parent.x + pad - 0.6 or t.r > parent.r - pad + 0.6 or t.y < parent.y + 2 - 0.6 or t.b > parent.b - 4 + 0.6:
            # Region labels sit in the header padding; allow that.
            if parent.kind == "region":
                continue
            errors.append(
                f"text '{t.name}' outside {parent.name}: text=({t.x:.1f},{t.y:.1f},{t.r:.1f},{t.b:.1f}) "
                f"box=({parent.x:.1f},{parent.y:.1f},{parent.r:.1f},{parent.b:.1f})"
            )

    # Text–text gap of 16px unless they share a parent (title+subtitle in a card).
    for i, a in enumerate(texts):
        for b in texts[i + 1 :]:
            if a.parent and a.parent == b.parent:
                continue
            if a.name in {"title", "subtitle"} and b.name in {"title", "subtitle", "legend"}:
                continue
            if {a.name, b.name} & {"title", "subtitle", "legend"}:
                # Title/subtitle/legend vs other text still needs gap, but title is far from nodes.
                if rects_overlap(a.inflate(4), b.inflate(4)):
                    errors.append(f"text overlap {a.name} vs {b.name}")
                continue
            if rects_overlap(a, b, TEXT_GAP):
                errors.append(f"text gap {a.name} vs {b.name} < {TEXT_GAP}px")

    # Node cards must not overlap each other.
    for i, a in enumerate(nodes):
        for b in nodes[i + 1 :]:
            if rects_overlap(a, b, 8):
                errors.append(f"node overlap {a.name} vs {b.name}")

    # Callouts must not overlap nodes or other callouts.
    for c in callouts:
        for n in nodes:
            if rects_overlap(c, n, 8):
                errors.append(f"callout {c.name} overlaps node {n.name}")
        for d in callouts:
            if d is c:
                continue
            if d.name < c.name:
                continue
            if rects_overlap(c, d, 8):
                errors.append(f"callout overlap {c.name} vs {d.name}")

    # Arrows must not hit icons or text (keep a clear gap). Junctions may share endpoints.
    skip_kinds = {"arrow", "region", "canvas", "shape"}
    for seg in scene.segs:
        for r in scene.rects:
            if r.kind in skip_kinds or r.kind == "arrow":
                continue
            if r.kind == "node":
                # Allowed to approach the node edge; not allowed to cross the interior
                # beyond a 1px sliver. We already stopped ARROW_CLEAR outside.
                inner = r.inflate(-1)
                if seg_intersects_rect(seg, inner, 0):
                    errors.append(f"arrow {seg.name} intersects node {r.name}")
                continue
            if r.kind in {"text", "icon"}:
                if seg_intersects_rect(seg, r, ARROW_CLEAR - 2):
                    errors.append(f"arrow {seg.name} intersects {r.kind} {r.name}")
            if r.kind in {"callout", "callout-box"}:
                if seg_intersects_rect(seg, r, 4):
                    errors.append(f"arrow {seg.name} intersects {r.name}")

    return errors


# ---------------------------------------------------------------------------
# Rasterize via CairoSVG
# ---------------------------------------------------------------------------


def rasterize(svg: str, png: Path, width: int, height: int) -> None:
    import cairosvg

    cairosvg.svg2png(
        bytestring=svg.encode("utf-8"),
        write_to=str(png),
        output_width=width,
        output_height=height,
        background_color="white",
    )


def main() -> int:
    scene = build()
    svg = "\n".join(scene.svg)
    errors = check(scene)
    OUT_SVG.write_text(svg)
    print(f"wrote {OUT_SVG}", flush=True)

    if errors:
        print(f"{len(errors)} layout check(s) failed:", file=sys.stderr)
        for e in errors[:40]:
            print(f"  - {e}", file=sys.stderr)
        if len(errors) > 40:
            print(f"  … {len(errors) - 40} more", file=sys.stderr)
        return 1

    print("layout checks passed", flush=True)

    rasterize(svg, OUT_PNG, W * 2, H * 2)
    rasterize(svg, OUT_PNG_838, 838, round(838 * H / W))

    print(f"wrote {OUT_PNG} {Image.open(OUT_PNG).size}", flush=True)
    print(f"wrote {OUT_PNG_838} {Image.open(OUT_PNG_838).size}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
