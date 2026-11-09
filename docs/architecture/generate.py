#!/usr/bin/env python3
"""Generate the Traceveil architecture diagram from measured layout.

Three horizontal lanes, each a left-to-right path. Browser vs server is a
tag on each node, not a column. Style references are color/type quality only.

Official product marks (GitHub, Gemini) are vendored from Simple Icons.
AI agents use a generic robot glyph, not a vendor logo.

Run from the repo root:

    python3 docs/architecture/generate.py

Needs Pillow and CairoSVG. Writes SVG + PNG and exits non-zero if text, icons,
or arrows intersect, if text overflows its box, if anything is clipped, or if
a callout is more than 40px from its arrow.
"""

from __future__ import annotations

import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image, ImageFont

ROOT = Path(__file__).resolve().parent
ICONS = ROOT / "icons"
OUT_SVG = ROOT / "traceveil-architecture.svg"
OUT_PNG = ROOT / "traceveil-architecture.png"
OUT_PNG_838 = ROOT / "traceveil-architecture-838.png"

W, H = 1800, 1180
MARGIN = 40
TEXT_GAP = 14
ARROW_CLEAR = 8
# Stop arrowheads this far from a card face that holds a top icon (matches side-entry
# breathing room once the 18px badge and marker are taken into account).
HEAD_GAP = 14
STROKE = 2.2
STROKE_DASH = 1.6
TITLE_SIZE = 18
SUB_SIZE = 13
CALLOUT_SIZE = 12
REGION_SIZE = 12
TAG_SIZE = 10
CALLOUT_ARROW_MAX = 40

FONT_REG_PATH = "/usr/share/fonts/truetype/macos/Inter-Regular.ttf"
FONT_MED_PATH = "/usr/share/fonts/truetype/macos/Inter-Medium.ttf"
FONT_SEM_PATH = "/usr/share/fonts/truetype/macos/Inter-SemiBold.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/macos/Inter-Bold.ttf"

INK = "#0F172A"
MUTED = "#64748B"
LINE = "#94A3B8"
LINE_STRONG = "#475569"
CARD = "#FFFFFF"
CARD_BORDER = "#E2E8F0"
REGION_BORDER = "#CBD5E1"
BADGE = "#EA580C"
BADGE_TEXT = "#FFFFFF"
CALLOUT_BG = "#FFF7ED"
CALLOUT_BORDER = "#FDBA74"
DASH = "6 5"

TAG_STYLE = {
    "Browser": ("#EEF2FF", "#4338CA"),
    "Server": ("#F0FDF4", "#166534"),
    "Host": ("#FFF7ED", "#9A3412"),
}


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
SHIELD_PATH = "M12 3.2 19 6v6.2c0 4.2-2.8 7.2-7 8.6-4.2-1.4-7-4.4-7-8.6V6l7-2.8z"
WINDOW_PATHS = [
    "M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v11A2.5 2.5 0 0 1 17.5 20h-11A2.5 2.5 0 0 1 4 17.5v-11z",
    "M4 8.5h16",
]


def weight_css(weight: str) -> str:
    return {"regular": "400", "medium": "500", "semibold": "600", "bold": "700"}[weight]


class Scene:
    def __init__(self) -> None:
        self.svg: list[str] = []
        self.rects: list[Rect] = []
        self.segs: list[Seg] = []
        self.callout_arrows: dict[str, str] = {}

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
            tx, box_x = x, x - tw / 2
        elif anchor == "end":
            tx, box_x = x, x - tw
        else:
            tx, box_x = x, x
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

    def trust_tag(self, cx: float, y: float, label: str, name: str) -> tuple[float, float]:
        tw, th, ascent = measure(label, TAG_SIZE, "semibold")
        w, h = tw + 12, th + 6
        bg, fg = TAG_STYLE[label]
        x = cx - w / 2
        self.svg.append(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="7" '
            f'fill="{bg}" stroke="{fg}" stroke-width="0.8"/>'
        )
        self.text_box(cx, y + (h - th) / 2 + ascent, label, TAG_SIZE, "semibold", fg, "middle", f"{name}:tag", name)
        return w, h

    def node_card(
        self,
        x: float,
        y: float,
        title: str,
        subtitle: str,
        icon: list[tuple[str, str, str]],
        icon_bg: str,
        name: str,
        trust: str,
        dashed: bool = False,
        min_w: float = 160,
    ) -> Rect:
        title_w, title_h, title_ascent = measure(title, TITLE_SIZE, "bold")
        sub_w, sub_h, sub_ascent = measure(subtitle, SUB_SIZE, "regular")
        tag_w, tag_h, _ = measure(trust, TAG_SIZE, "semibold")
        pad_x, pad_y = 12, 10
        icon_r = 18
        inner_w = max(min_w - 2 * pad_x, title_w, sub_w, tag_w + 12, icon_r * 2)
        w = inner_w + 2 * pad_x
        h = pad_y + icon_r * 2 + 6 + title_h + 3 + sub_h + 8 + (tag_h + 6) + pad_y
        dash = DASH if dashed else None
        fill = "#FCFCFD" if dashed else CARD
        stroke = "#94A3B8" if dashed else CARD_BORDER
        card = self.round_rect(x, y, w, h, 14, fill, stroke, 1.3, dash, name, "node")
        cx = x + w / 2
        icon_cy = y + pad_y + icon_r
        self.icon_badge(cx, icon_cy, icon_r, icon_bg, icon, f"{name}:icon", name)
        title_y = icon_cy + icon_r + 6 + title_ascent
        self.text_box(cx, title_y, title, TITLE_SIZE, "bold", INK, "middle", f"{name}:title", name)
        sub_y = title_y + (title_h - title_ascent) + 3 + sub_ascent
        self.text_box(cx, sub_y, subtitle, SUB_SIZE, "regular", MUTED, "middle", f"{name}:sub", name)
        tag_y = sub_y + (sub_h - sub_ascent) + 8
        self.trust_tag(cx, tag_y, trust, name)
        last = [r for r in self.rects if r.parent == name and r.kind == "text"][-1]
        if last.b + pad_y - y > h + 0.5:
            raise SystemExit(f"node {name} height too small for text")
        return card

    def callout(self, x: float, y: float, number: int, text: str, name: str, arrow: str) -> Rect:
        tw, th, ascent = measure(text, CALLOUT_SIZE, "medium")
        badge_r = 9
        pad_x, pad_y = 8, 5
        gap = 6
        box_w = pad_x + tw + pad_x
        box_h = pad_y + th + pad_y
        group_h = max(badge_r * 2, box_h)
        badge_cx = x + badge_r + 4
        badge_cy = y + group_h / 2
        box_x = badge_cx + badge_r + gap
        box_y = y + (group_h - box_h) / 2
        group = self.add_rect(Rect(x, y, box_x + box_w - x, group_h, "callout", name))
        self.callout_arrows[name] = arrow
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
            box_x + pad_x, box_y + pad_y + ascent, text, CALLOUT_SIZE, "medium", "#9A3412", "start", f"{name}:label", name
        )
        return group

    def callout_size(self, text: str) -> tuple[float, float]:
        tw, _, _ = measure(text, CALLOUT_SIZE, "medium")
        return 4 + 18 + 6 + 8 + tw + 8, 30

    def callout_above(self, x1: float, x2: float, y: float, number: int, text: str, name: str, arrow: str) -> Rect:
        """Sit the callout directly above a horizontal stroke, ~14px gap."""
        gw, gh = self.callout_size(text)
        cx = (x1 + x2) / 2
        return self.callout(cx - gw / 2, y - 14 - gh, number, text, name, arrow)

    def callout_beside(
        self,
        x: float,
        y1: float,
        y2: float,
        number: int,
        text: str,
        name: str,
        arrow: str,
        side: str = "left",
    ) -> Rect:
        """Sit the callout beside a vertical stroke, mid-gap, ~8px off the line."""
        tw, th, _ = measure(text, CALLOUT_SIZE, "medium")
        gw = 4 + 18 + 6 + 8 + tw + 8
        gh = 30
        mid_y = (y1 + y2) / 2
        cx = x + 8 if side == "right" else x - 8 - gw
        return self.callout(cx, mid_y - gh / 2, number, text, name, arrow)

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
        self.round_rect(x, y, w, h, 16, fill, stroke, 1.3, dash, name, "region")
        self.text_box(x + w - 16, y + 20, label, REGION_SIZE, "semibold", MUTED, "end", f"{name}:label", name)
        return self.rects[-2]

    def arrow(self, points: list[tuple[float, float]], name: str, dashed: bool = False, double: bool = False) -> None:
        if len(points) < 2:
            raise SystemExit(f"arrow {name} needs 2+ points")
        d = f"M {points[0][0]:.2f} {points[0][1]:.2f}"
        for x, y in points[1:]:
            d += f" L {x:.2f} {y:.2f}"
        dash_attr = f'stroke-dasharray="{DASH}"' if dashed else ""
        end = "url(#arrow-dash)" if dashed else "url(#arrow)"
        start = 'marker-start="url(#arrow-start-dash)"' if double else ""
        stroke = LINE if dashed else LINE_STRONG
        width = STROKE_DASH if dashed else STROKE
        self.svg.append(
            f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{width}" '
            f'stroke-linejoin="round" stroke-linecap="round" marker-end="{end}" {start} {dash_attr}/>'
        )
        for i in range(len(points) - 1):
            x1, y1 = points[i]
            x2, y2 = points[i + 1]
            self.segs.append(Seg(x1, y1, x2, y2, name))
            pad = STROKE / 2
            self.add_rect(
                Rect(min(x1, x2) - pad, min(y1, y2) - pad, abs(x2 - x1) + STROKE, abs(y2 - y1) + STROKE, "arrow", f"{name}:{i}")
            )


def build() -> Scene:
    s = Scene()
    s.svg.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        f'role="img" aria-labelledby="title desc">'
    )
    s.svg.append("<defs>")
    s.svg.append(
        '<marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">'
        f'<path d="M0,0.4 L9.2,5 L0,9.6" fill="{LINE_STRONG}"/>'
        "</marker>"
    )
    s.svg.append(
        '<marker id="arrow-dash" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">'
        f'<path d="M0,0.4 L9.2,5 L0,9.6" fill="{LINE}"/>'
        "</marker>"
    )
    s.svg.append(
        '<marker id="arrow-start-dash" markerWidth="10" markerHeight="10" refX="1" refY="5" orient="auto">'
        f'<path d="M9.2,0.4 L0,5 L9.2,9.6" fill="{LINE}"/>'
        "</marker>"
    )
    s.svg.append(
        "<style>"
        "svg { font-family: Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; }"
        "</style>"
    )
    s.svg.append("</defs>")
    s.round_rect(0, 0, W, H, 0, "#FFFFFF", "#FFFFFF", 0, None, "canvas", "canvas")
    s.rects[-1].ignore_vs = frozenset({"*"})

    s.text_box(W / 2, 62, "How a Traceveil investigation run works", 22, "bold", INK, "middle", "title")
    s.text_box(
        W / 2,
        84,
        "Three lanes, left to right. Tags mark where each step runs. Dashed lanes are optional.",
        13,
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

    # ----- Lane bands -----
    s.region(40, 100, 1720, 548, "Lane A  ·  Main investigation run", "lane-a")
    s.region(40, 672, 1720, 200, "Lane B  ·  Optional: tenant isolation chat", "lane-b", True)
    s.region(40, 892, 1720, 196, "Lane C  ·  Optional: MCP audit and guard", "lane-c", True)

    # ----- Lane A nodes -----
    spine_y = 308
    rail_a = spine_y + 4
    you = s.node_card(56, spine_y, "You", "Signed-in investigator", user_icon, "#334155", "you", "Browser")
    console = s.node_card(you.r + 52, spine_y, "Console", "Workspace after sign-in", window_icon, "#4F46E5", "console", "Browser")
    scan = s.node_card(console.r + 76, spine_y, "Scan API", "POST /api/application-scan", scan_icon, "#0284C7", "scan", "Server")
    github = s.node_card(scan.r + 72, 126, "GitHub collector", "Snapshot; optional PAT vault", github_icon, "#E2E8F0", "github", "Server")
    live = s.node_card(scan.r + 72, 500, "Live HTTPS probes", "Four GETs on port 443", globe_icon, "#0F766E", "live", "Server")
    fork_r = max(github.r, live.r)
    graph = s.node_card(fork_r + 56, spine_y, "Graph engine", "Static rules, evidence IDs", scan_icon, "#7C3AED", "graph", "Server")
    agents = s.node_card(graph.r + 48, spine_y, "Report agents", "Four template write-ups", robot_icon, "#0F766E", "agents", "Server")
    canvas = s.node_card(agents.r + 48, spine_y, "Results canvas", "React Flow + Dagre layout", window_icon, "#4338CA", "canvas-node", "Browser")

    store = s.node_card(scan.x, scan.b + 64, "Local JSON store", "application_scans row", file_icon, "#D97706", "store", "Server")

    # ----- Lane B nodes (hang under Console) -----
    isolation = s.node_card(
        console.x + 24, 720, "Isolation agent", "Server fn; drafts RLS", robot_icon, "#5B21B6", "isolation", "Server", True
    )
    gemini = s.node_card(
        isolation.r + 56,
        isolation.y,
        "Google Gemini",
        "Optional frontier API",
        gemini_icon,
        "#EDE9FE",
        "gemini",
        "Host",
        True,
    )

    # ----- Lane C nodes (Console sidebar → /mcp-audits; drop lands on that page) -----
    mcp_y = 940
    mcp_drop_x = isolation.x - 18
    mcp_page = s.node_card(
        mcp_drop_x - 80, mcp_y, "MCP audits", "/mcp-audits page", window_icon, "#9A3412", "mcp-page", "Browser", True
    )
    mcp_scan = s.node_card(
        mcp_page.r + 64, mcp_y, "MCP ingest", "POST /api/scan; saves audit", scan_icon, "#C2410C", "mcp-scan", "Server", True
    )
    guard = s.node_card(
        mcp_scan.r + 64,
        mcp_y,
        "Tool guard",
        "Checks allowlist, then tools/call",
        lock_icon,
        "#BE123C",
        "guard",
        "Server",
        True,
    )

    # ----- Lane A arrows (rail along the top of the spine cards so callouts sit just above) -----
    s.arrow([(you.r + 3, rail_a), (console.x - 3, rail_a)], "a1")
    c1 = s.callout_above(you.r, console.x, rail_a, 1, "Sign in; session stays here", "c1", "a1")

    s.arrow([(console.r + 3, rail_a), (scan.x - 3, rail_a)], "a2")
    c2_text = "Pick repo or live app"
    c2_w, c2_h = s.callout_size(c2_text)
    c3_text = "Authenticated scan starts"
    c3_w, c3_h = s.callout_size(c3_text)
    # c2 left of the Console→Scan stroke, c3 right of it — neither on the line nor on the fork.
    c3_x = (scan.x - 3) + 8
    c2_x = min(c3_x - 8 - c2_w, max(c1.r + 8, (console.r + 3) - 8 - c2_w))
    s.callout(c2_x, rail_a - 14 - c2_h, 2, c2_text, "c2", "a2")
    s.callout(c3_x, rail_a - 14 - c3_h, 3, c3_text, "c3", "a2")

    fork_x = (scan.r + github.x) / 2
    s.arrow(
        [
            (scan.r + 3, rail_a),
            (fork_x, rail_a),
            (fork_x, github.cy),
            (github.x - 3, github.cy),
        ],
        "a-fork-gh",
    )
    s.arrow([(fork_x, rail_a), (fork_x, live.cy), (live.x - 3, live.cy)], "a-fork-live")
    s.callout_beside(fork_x, scan.b + 10, live.y - 10, 4, "GitHub files or live HTTPS", "c4", "a-fork-live", "right")

    join_x = (fork_r + graph.x) / 2
    s.arrow(
        [
            (github.r + 3, github.cy),
            (join_x, github.cy),
            (join_x, rail_a),
            (graph.x - 3, rail_a),
        ],
        "a-join-gh",
    )
    s.arrow([(live.r + 3, live.cy), (join_x, live.cy), (join_x, rail_a)], "a-join-live")
    c5_text = "Static rules bind evidence"
    c5_w, _ = s.callout_size(c5_text)
    s.callout(join_x + 8, rail_a - 14 - 30, 5, c5_text, "c5", "a-join-gh")

    s.arrow([(scan.cx, scan.b + 8), (scan.cx, store.y - HEAD_GAP)], "a-save")
    s.callout_beside(scan.cx, scan.b, store.y, 6, "Scan API writes the record", "c6", "a-save", "left")

    s.arrow([(graph.r + 3, rail_a), (agents.x - 3, rail_a)], "a-agents")
    c7_text = "Agents stream template reports"
    c7_w, _ = s.callout_size(c7_text)
    c7_x = max(join_x + 8 + c5_w + 8, (graph.r + agents.x) / 2 - c7_w / 2)
    s.callout(c7_x, rail_a - 14 - 30, 7, c7_text, "c7", "a-agents")

    s.arrow([(agents.r + 3, rail_a), (canvas.x - 3, rail_a)], "a-canvas")
    c8_text = "Canvas draws the graph"
    c8_w, _ = s.callout_size(c8_text)
    c8_x = max(c7_x + c7_w + 8, (agents.r + canvas.x) / 2 - c8_w / 2)
    s.callout(c8_x, rail_a - 14 - 30, 8, c8_text, "c8", "a-canvas")

    # ----- Lane B: short drop from Console, then two-headed Isolation ↔ Gemini -----
    rail_b = isolation.y + 4
    s.arrow([(console.cx, console.b + 3), (console.cx, isolation.y - 3)], "d-iso-drop", True)
    s.arrow(
        [(isolation.r + 3, rail_b), (gemini.x - 3, rail_b)],
        "d-iso-gemini",
        True,
        double=True,
    )
    s.callout_above(isolation.r, gemini.x, rail_b, 9, "Isolation tab calls Gemini", "c9", "d-iso-gemini")

    # ----- Lane C: from Console bottom-center (sidebar Link to /mcp-audits), around Isolation -----
    rail_c = mcp_page.y + 4
    mcp_drop_x = mcp_page.cx
    s.arrow(
        [
            (console.cx, console.b + 3),
            (mcp_drop_x, console.b + 3),
            (mcp_drop_x, mcp_page.y - HEAD_GAP),
        ],
        "d-mcp-drop",
        True,
    )
    s.arrow([(mcp_page.r + 3, rail_c), (mcp_scan.x - 3, rail_c)], "d-mcp-1", True)
    s.arrow([(mcp_scan.r + 3, rail_c), (guard.x - 3, rail_c)], "d-mcp-2", True)
    c10_text = "Optional MCP audit and guard"
    c10_w, c10_h = s.callout_size(c10_text)
    c10_x = max(mcp_page.cx + 12, (mcp_page.r + mcp_scan.x) / 2 - c10_w / 2)
    s.callout(c10_x, rail_c - 14 - c10_h, 10, c10_text, "c10", "d-mcp-1")

    s.text_box(
        40,
        1136,
        "Browser = UI  ·  Server = Node process (no repository code executed)  ·  Host = outbound API.  Dashed lanes need a Console action plus config.  Callouts 1–10 match the README.",
        12,
        "regular",
        MUTED,
        "start",
        "legend",
    )

    s.svg.append("</svg>")
    return s


def rects_overlap(a: Rect, b: Rect, gap: float = 0) -> bool:
    return not (a.r + gap <= b.x or b.r + gap <= a.x or a.b + gap <= b.y or b.b + gap <= a.y)


def seg_intersects_rect(seg: Seg, rect: Rect, clearance: float) -> bool:
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
    return False


def rect_seg_dist(rect: Rect, seg: Seg) -> float:
    """Minimum distance from a rectangle to a segment (0 if they touch or cross)."""
    if seg_intersects_rect(seg, rect, 0):
        return 0.0
    corners = [
        (rect.x, rect.y),
        (rect.r, rect.y),
        (rect.x, rect.b),
        (rect.r, rect.b),
        (rect.cx, rect.y),
        (rect.cx, rect.b),
        (rect.x, rect.cy),
        (rect.r, rect.cy),
    ]
    d = min(point_seg_dist(px, py, seg) for px, py in corners)
    for px, py in ((seg.x1, seg.y1), (seg.x2, seg.y2)):
        dx = 0.0 if rect.x <= px <= rect.r else (rect.x - px if px < rect.x else px - rect.r)
        dy = 0.0 if rect.y <= py <= rect.b else (rect.y - py if py < rect.y else py - rect.b)
        d = min(d, math.hypot(dx, dy))
    return d


def point_seg_dist(px: float, py: float, seg: Seg) -> float:
    x1, y1, x2, y2 = seg.x1, seg.y1, seg.x2, seg.y2
    dx, dy = x2 - x1, y2 - y1
    length2 = dx * dx + dy * dy
    if length2 < 1e-6:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / length2))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


def check(scene: Scene) -> list[str]:
    errors: list[str] = []
    texts = [r for r in scene.rects if r.kind == "text"]
    icons = [r for r in scene.rects if r.kind == "icon"]
    nodes = [r for r in scene.rects if r.kind == "node"]
    callouts = [r for r in scene.rects if r.kind == "callout"]

    canvas = Rect(MARGIN, MARGIN, W - 2 * MARGIN, H - 2 * MARGIN, "canvas", "safe")

    def in_canvas(r: Rect) -> bool:
        return r.x >= canvas.x - 0.5 and r.y >= canvas.y - 0.5 and r.r <= canvas.r + 0.5 and r.b <= canvas.b + 0.5

    for r in texts + icons + nodes + callouts:
        if r.name in {"title", "subtitle", "legend"} or (
            r.parent in {None, "title", "subtitle", "legend"} and r.kind == "text"
        ):
            if not (r.x >= MARGIN - 0.5 and r.r <= W - MARGIN + 0.5 and r.y >= MARGIN - 0.5 and r.b <= H - MARGIN + 0.5):
                errors.append(f"clipped {r.name} ({r.x:.1f},{r.y:.1f} {r.w:.1f}x{r.h:.1f})")
            continue
        if not in_canvas(r):
            errors.append(f"clipped {r.name} ({r.x:.1f},{r.y:.1f} {r.w:.1f}x{r.h:.1f})")

    for t in texts:
        if not t.parent:
            continue
        parent = next(
            (r for r in scene.rects if r.name == t.parent and r.kind in {"node", "callout", "callout-box", "region"}),
            None,
        )
        if parent is None:
            parent = next((r for r in scene.rects if r.name == f"{t.parent}:box"), None)
        if parent is None:
            continue
        pad = 4 if parent.kind == "region" else 4
        if parent.kind == "region":
            continue
        if t.x < parent.x + pad - 0.8 or t.r > parent.r - pad + 0.8 or t.y < parent.y + 1 or t.b > parent.b - 3:
            if t.name.endswith(":num"):
                continue
            errors.append(
                f"text '{t.name}' outside {parent.name}: text=({t.x:.1f},{t.y:.1f},{t.r:.1f},{t.b:.1f}) "
                f"box=({parent.x:.1f},{parent.y:.1f},{parent.r:.1f},{parent.b:.1f})"
            )

    for i, a in enumerate(texts):
        for b in texts[i + 1 :]:
            if a.parent and a.parent == b.parent:
                continue
            if a.name in {"title", "subtitle"} and b.name in {"title", "subtitle", "legend"}:
                continue
            if {a.name, b.name} & {"title", "subtitle", "legend"}:
                if rects_overlap(a.inflate(4), b.inflate(4)):
                    errors.append(f"text overlap {a.name} vs {b.name}")
                continue
            if rects_overlap(a, b, TEXT_GAP):
                errors.append(f"text gap {a.name} vs {b.name} < {TEXT_GAP}px")

    for i, a in enumerate(nodes):
        for b in nodes[i + 1 :]:
            if rects_overlap(a, b, 8):
                errors.append(f"node overlap {a.name} vs {b.name}")

    for c in callouts:
        for n in nodes:
            if rects_overlap(c, n, 8):
                errors.append(f"callout {c.name} overlaps node {n.name}")
        for d in callouts:
            if d is c or d.name < c.name:
                continue
            if rects_overlap(c, d, 8):
                errors.append(f"callout overlap {c.name} vs {d.name}")

    skip_kinds = {"arrow", "region", "canvas", "shape"}
    for seg in scene.segs:
        for r in scene.rects:
            if r.kind in skip_kinds or r.kind == "arrow":
                continue
            if r.kind == "node":
                inner = r.inflate(-1)
                if seg_intersects_rect(seg, inner, 0):
                    errors.append(f"arrow {seg.name} intersects node {r.name}")
                continue
            if r.kind in {"text", "icon"} and r.parent and r.parent.startswith("lane-"):
                continue
            if r.kind in {"text", "icon"} and seg_intersects_rect(seg, r, ARROW_CLEAR - 2):
                errors.append(f"arrow {seg.name} intersects {r.kind} {r.name}")
            if r.kind in {"callout", "callout-box"} and seg_intersects_rect(seg, r, 4):
                errors.append(f"arrow {seg.name} intersects {r.name}")

    # Each callout must sit within 40px of its named arrow (nearest point on the chip).
    segs_by_name: dict[str, list[Seg]] = {}
    for seg in scene.segs:
        segs_by_name.setdefault(seg.name, []).append(seg)
    for c in callouts:
        arrow = scene.callout_arrows.get(c.name)
        if not arrow:
            errors.append(f"callout {c.name} has no arrow mapping")
            continue
        segs = segs_by_name.get(arrow, [])
        if not segs:
            errors.append(f"callout {c.name} arrow '{arrow}' has no segments")
            continue
        dist = min(rect_seg_dist(c, seg) for seg in segs)
        if dist > CALLOUT_ARROW_MAX:
            errors.append(f"callout {c.name} is {dist:.1f}px from arrow {arrow} (max {CALLOUT_ARROW_MAX})")

    return errors


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
    if "--dump" in sys.argv:
        for r in scene.rects:
            if r.kind in {"node", "callout"}:
                print(f"{r.kind:8} {r.name:16} x={r.x:7.1f} y={r.y:7.1f} r={r.r:7.1f} b={r.b:7.1f}")
        for seg in scene.segs:
            print(f"seg {seg.name:14} ({seg.x1:.1f},{seg.y1:.1f})->({seg.x2:.1f},{seg.y2:.1f})")

    if errors:
        print(f"{len(errors)} layout check(s) failed:", file=sys.stderr)
        for e in errors[:50]:
            print(f"  - {e}", file=sys.stderr)
        if len(errors) > 50:
            print(f"  … {len(errors) - 50} more", file=sys.stderr)
        return 1

    print("layout checks passed", flush=True)
    rasterize(svg, OUT_PNG, W * 2, H * 2)
    rasterize(svg, OUT_PNG_838, 838, round(838 * H / W))
    print(f"wrote {OUT_PNG} {Image.open(OUT_PNG).size}", flush=True)
    print(f"wrote {OUT_PNG_838} {Image.open(OUT_PNG_838).size}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
