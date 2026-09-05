"""
HoneyShield dashboard design system.

One place for the visual language, so pages compose components instead of
hand-rolling markup. Streamlit's defaults are a prototyping aesthetic; a SOC
console is read under time pressure, often for hours, so this leans on a dark
low-glare ground, one warm accent reserved for brand and action, and a fixed
severity palette that means the same thing on every page.

SECURITY NOTE — read before adding anything here.
`unsafe_allow_html` appears in this module. Every use renders text that this
codebase controls: static CSS, hard-coded labels, and numbers formatted from
integers. Attacker-supplied values (usernames, passwords, paths, User-Agents)
must NEVER be passed to these helpers — they belong in `st.dataframe`, which
treats cell contents as inert text. See HONEYSHIELD_PROJECT.md section 6
point 3. `esc()` below is the guard for the rare case where a caller must
interpolate a value that isn't a literal.
"""

from html import escape as _escape
from typing import Iterable, Optional, Sequence

import streamlit as st

# ── Palette ────────────────────────────────────────────────────────────────
BG = "#0B0F17"
SURFACE = "#131A27"
SURFACE_2 = "#1A2231"
BORDER = "#232D3F"
TEXT = "#E6EAF2"
MUTED = "#8A97AD"
ACCENT = "#F5A524"       # honey — brand and primary action only
ACCENT_DIM = "#7A5310"

SEVERITY = {
    "CRITICAL": "#F0426B",
    "HIGH": "#FF7A45",
    "MEDIUM": "#F5A524",
    "LOW": "#3DD68C",
    "INFO": "#4A9EFF",
}


def esc(value) -> str:
    """HTML-escape anything that is not a hard-coded literal."""
    return _escape(str(value), quote=True)


_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {{
  --bg: {BG};
  --surface: {SURFACE};
  --surface-2: {SURFACE_2};
  --border: {BORDER};
  --text: {TEXT};
  --muted: {MUTED};
  --accent: {ACCENT};
}}

html, body, [class*="css"], .stApp {{
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  -webkit-font-smoothing: antialiased;
}}
.stApp {{ background: var(--bg); }}

/* Streamlit chrome we never want in a local SOC console. */
[data-testid="stToolbar"], [data-testid="stDecoration"],
[data-testid="stStatusWidget"], #MainMenu, footer, header {{ display: none !important; }}

/* Roomier canvas — the default top padding wastes a third of the fold. */
.block-container {{ padding: 2.25rem 2.75rem 4rem !important; max-width: 1500px; }}

/* ── Typography scale ─────────────────────────────────────────────────── */
h1, h2, h3, h4 {{ font-family: 'Inter', sans-serif; color: var(--text); letter-spacing: -0.02em; }}
h1 {{ font-size: 1.9rem !important; font-weight: 700 !important; }}
h2 {{ font-size: 1.3rem !important; font-weight: 600 !important; }}
h3 {{ font-size: 1.05rem !important; font-weight: 600 !important; }}
p, li, label, .stMarkdown {{ color: var(--text); }}

/* Streamlit renders anchor links next to headers; they add clutter. */
.stMarkdown a[href^="#"] svg {{ display: none; }}

/* ── Sidebar ──────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {{
  background: {SURFACE}; border-right: 1px solid var(--border);
}}
[data-testid="stSidebar"] .block-container {{ padding: 1.25rem 1rem !important; }}

/* ── Page header ──────────────────────────────────────────────────────── */
.hs-header {{ margin: 0 0 1.75rem; }}
.hs-header .hs-eyebrow {{
  font-size: .7rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase;
  color: var(--accent); margin-bottom: .4rem;
}}
.hs-header h1 {{ margin: 0 0 .3rem !important; font-size: 1.9rem !important; }}
.hs-header .hs-sub {{ color: var(--muted); font-size: .93rem; max-width: 68ch; line-height: 1.55; }}

/* ── KPI cards ────────────────────────────────────────────────────────── */
.hs-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: .9rem; margin-bottom: 1.6rem; }}
.hs-kpi {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border); border-radius: 12px; padding: 1.05rem 1.15rem;
  position: relative; overflow: hidden;
  animation: hs-rise .38s cubic-bezier(.22,.61,.36,1) both;
}}
.hs-kpi::after {{
  content: ''; position: absolute; inset: 0 auto auto 0; width: 3px; height: 100%;
  background: var(--tone, var(--accent)); opacity: .85;
}}
.hs-kpi .hs-k-label {{
  font-size: .72rem; font-weight: 600; letter-spacing: .09em; text-transform: uppercase;
  color: var(--muted); margin-bottom: .45rem;
}}
.hs-kpi .hs-k-value {{
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 1.95rem; font-weight: 500; line-height: 1.1; color: var(--text);
}}
.hs-kpi .hs-k-note {{ font-size: .76rem; color: var(--muted); margin-top: .35rem; }}
.hs-kpi:nth-child(2) {{ animation-delay: .05s; }}
.hs-kpi:nth-child(3) {{ animation-delay: .1s; }}
.hs-kpi:nth-child(4) {{ animation-delay: .15s; }}
.hs-kpi:nth-child(5) {{ animation-delay: .2s; }}

@keyframes hs-rise {{ from {{ opacity: 0; transform: translateY(8px); }} to {{ opacity: 1; transform: none; }} }}

/* ── Section heading ──────────────────────────────────────────────────── */
.hs-section {{ margin: 2.1rem 0 .9rem; }}
.hs-section h2 {{ margin: 0 !important; display: flex; align-items: center; gap: .55rem; }}
.hs-section .hs-s-sub {{ color: var(--muted); font-size: .85rem; margin-top: .3rem; line-height: 1.5; max-width: 74ch; }}
.hs-rule {{ height: 1px; background: var(--border); border: 0; margin: 2.1rem 0 0; }}

/* ── Empty state ──────────────────────────────────────────────────────── */
.hs-empty {{
  border: 1px dashed var(--border); border-radius: 12px; background: rgba(255,255,255,.012);
  padding: 2.3rem 1.5rem; text-align: center; animation: hs-rise .4s ease both;
}}
.hs-empty .hs-e-icon {{ font-size: 1.7rem; opacity: .75; margin-bottom: .6rem; }}
.hs-empty .hs-e-title {{ font-weight: 600; color: var(--text); margin-bottom: .35rem; font-size: 1rem; }}
.hs-empty .hs-e-body {{ color: var(--muted); font-size: .88rem; line-height: 1.6; max-width: 56ch; margin: 0 auto; }}

/* ── Badges ───────────────────────────────────────────────────────────── */
.hs-badge {{
  display: inline-block; padding: .16rem .55rem; border-radius: 999px;
  font-size: .72rem; font-weight: 600; letter-spacing: .04em;
  border: 1px solid currentColor; background: rgba(255,255,255,.04);
}}

/* ── Data tables ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {{ border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
[data-testid="stDataFrame"] * {{ font-family: 'JetBrains Mono', ui-monospace, monospace !important; font-size: .82rem !important; }}

/* ── Inputs & buttons ─────────────────────────────────────────────────── */
.stTextInput input, .stSelectbox div[data-baseweb="select"] > div, .stNumberInput input {{
  background: var(--surface-2) !important; border: 1px solid var(--border) !important;
  border-radius: 8px !important; color: var(--text) !important;
}}
.stTextInput input:focus {{ border-color: var(--accent) !important; box-shadow: 0 0 0 2px rgba(245,165,36,.15) !important; }}
.stTextInput input::placeholder {{ color: #5C6883 !important; }}

.stButton > button {{
  border-radius: 8px; font-weight: 600; font-size: .88rem; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text); transition: all .16s ease; padding: .5rem 1.1rem;
}}
.stButton > button:hover {{ border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }}
.stButton > button[kind="primary"] {{
  background: var(--accent); border-color: var(--accent); color: #1A1206;
}}
.stButton > button[kind="primary"]:hover {{ filter: brightness(1.08); color: #1A1206; }}

/* Streamlit's stock alert boxes, toned to the palette. */
[data-testid="stAlert"] {{ border-radius: 10px; border: 1px solid var(--border); background: var(--surface); }}

/* ── Login ────────────────────────────────────────────────────────────── */
.hs-login-brand {{ text-align: center; margin: 3.5rem 0 1.6rem; animation: hs-rise .45s ease both; }}
.hs-login-brand .hs-logo {{ font-size: 2.6rem; line-height: 1; margin-bottom: .7rem; }}
.hs-login-brand h1 {{ margin: 0 !important; font-size: 1.75rem !important; letter-spacing: -.025em; }}
.hs-login-brand .hs-tag {{ color: var(--muted); font-size: .88rem; margin-top: .45rem; }}
.hs-login-note {{
  text-align: center; color: var(--muted); font-size: .78rem; margin-top: 1.4rem; line-height: 1.6;
}}
</style>
"""


def inject(authenticated: bool = True) -> None:
    """
    Apply the design system. Call once per page, before rendering anything.

    `authenticated=False` additionally hides the page navigation. Streamlit
    lists every file in pages/ automatically, which on the login screen
    advertises the console's structure to someone who has not authenticated.
    Each page still gates independently — this is defence in depth and basic
    polish, never the access control itself.
    """
    st.markdown(_CSS, unsafe_allow_html=True)
    if not authenticated:
        st.markdown(
            "<style>[data-testid='stSidebarNav'], [data-testid='stSidebar'] "
            "{display:none !important;}</style>",
            unsafe_allow_html=True,
        )


def page_header(icon: str, title: str, subtitle: str = "", eyebrow: str = "") -> None:
    """Consistent page masthead. All arguments must be literals, never data."""
    parts = ['<div class="hs-header">']
    if eyebrow:
        parts.append(f'<div class="hs-eyebrow">{esc(eyebrow)}</div>')
    parts.append(f"<h1>{esc(icon)} {esc(title)}</h1>")
    if subtitle:
        parts.append(f'<div class="hs-sub">{esc(subtitle)}</div>')
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def kpis(items: Sequence[dict]) -> None:
    """
    Render a row of KPI cards.

    Each item: {"label": str, "value": str|int, "note": str, "tone": colour}.
    Values are numbers or our own short strings — never attacker text.
    """
    cards = []
    for it in items:
        tone = it.get("tone", ACCENT)
        note = f'<div class="hs-k-note">{esc(it["note"])}</div>' if it.get("note") else ""
        cards.append(
            f'<div class="hs-kpi" style="--tone:{esc(tone)}">'
            f'<div class="hs-k-label">{esc(it["label"])}</div>'
            f'<div class="hs-k-value">{esc(it["value"])}</div>{note}</div>'
        )
    st.markdown(f'<div class="hs-kpis">{"".join(cards)}</div>', unsafe_allow_html=True)


def section(title: str, subtitle: str = "", rule: bool = True) -> None:
    """A titled section break with optional explanatory subtitle."""
    if rule:
        st.markdown('<hr class="hs-rule"/>', unsafe_allow_html=True)
    sub = f'<div class="hs-s-sub">{esc(subtitle)}</div>' if subtitle else ""
    st.markdown(
        f'<div class="hs-section"><h2>{esc(title)}</h2>{sub}</div>', unsafe_allow_html=True
    )


def empty_state(icon: str, title: str, body: str) -> None:
    """
    A deliberate, explanatory empty state.

    Most of this console is legitimately empty early in a capture window. An
    unexplained blank panel reads as broken; saying *why* it is empty and what
    would fill it is the difference between "no data" and "nothing has
    happened yet, and that is the expected reading".
    """
    st.markdown(
        f'<div class="hs-empty"><div class="hs-e-icon">{esc(icon)}</div>'
        f'<div class="hs-e-title">{esc(title)}</div>'
        f'<div class="hs-e-body">{esc(body)}</div></div>',
        unsafe_allow_html=True,
    )


def severity_tone(verdict: Optional[str]) -> str:
    return SEVERITY.get((verdict or "").upper(), MUTED)


def style_chart(fig, height: int = 320):
    """Apply the palette to a Plotly figure so charts match the console."""
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=MUTED, size=12),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER, linecolor=BORDER),
        yaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER, linecolor=BORDER),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=MUTED)),
        colorway=[ACCENT, "#4A9EFF", "#3DD68C", "#F0426B", "#A78BFA", "#FF7A45"],
    )
    return fig


def sidebar_identity(username: str) -> None:
    """Brand block + signed-in identity for the sidebar."""
    st.sidebar.markdown(
        '<div style="display:flex;align-items:center;gap:.55rem;margin-bottom:1.2rem">'
        '<span style="font-size:1.5rem">🍯</span>'
        '<div><div style="font-weight:700;font-size:1rem;letter-spacing:-.02em">HoneyShield</div>'
        f'<div style="font-size:.7rem;color:{MUTED};letter-spacing:.09em;text-transform:uppercase">'
        "SOC Console</div></div></div>",
        unsafe_allow_html=True,
    )
    st.sidebar.markdown(
        f'<div style="border:1px solid {BORDER};border-radius:9px;padding:.6rem .75rem;'
        f'background:{SURFACE_2};margin-bottom:.75rem">'
        f'<div style="font-size:.68rem;color:{MUTED};letter-spacing:.09em;'
        'text-transform:uppercase;margin-bottom:.15rem">Signed in</div>'
        f'<div style="font-weight:600;font-size:.88rem">{esc(username)}</div></div>',
        unsafe_allow_html=True,
    )
