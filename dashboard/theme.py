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

/* Streamlit chrome we never want in a local SOC console.
   Hide the individual toolbar ITEMS, never the toolbar or the header itself:
   in Streamlit 1.58 the sidebar expand control is a child of stToolbar, which
   is a child of stHeader, so hiding either ancestor removes the only way to
   reopen a collapsed sidebar — a child of a display:none parent cannot be
   revived by any rule on the child. Verified against the shipped bundle:
   stHeader > stToolbar > … > stExpandSidebarButton. */
[data-testid="stAppDeployButton"], [data-testid="stMainMenu"],
[data-testid="stToolbarActions"], [data-testid="stStatusWidget"],
[data-testid="stDecoration"], #MainMenu, footer {{ display: none !important; }}

/* Toolbar stays in the DOM purely to carry the expand control. */
[data-testid="stToolbar"] {{
  background: transparent !important; box-shadow: none !important;
  right: auto !important; left: 0; padding: 0 !important;
}}

header[data-testid="stHeader"] {{
  background: transparent !important; height: 0 !important; min-height: 0 !important;
  box-shadow: none !important; border: none !important;
  /* overflow must stay visible: the expand control lives inside this header,
     and a zero-height ancestor with hidden overflow would clip it away again. */
  overflow: visible !important;
}}

/* The way back when the sidebar is collapsed. Streamlit has renamed this
   control across versions, so every known id is targeted. */
[data-testid="stSidebarCollapsedControl"],
[data-testid="stExpandSidebarButton"],
[data-testid="collapsedControl"] {{
  display: flex !important; visibility: visible !important; opacity: 1 !important;
  position: fixed !important; top: 14px; left: 14px; z-index: 1000;
  align-items: center; justify-content: center;
  background: rgba(19,26,39,.92) !important;
  border: 1px solid rgba(255,255,255,.11) !important; border-radius: 10px;
  -webkit-backdrop-filter: blur(12px); backdrop-filter: blur(12px);
  box-shadow: 0 8px 22px -10px rgba(0,0,0,.85);
  transition: border-color .15s ease, background .15s ease;
}}
[data-testid="stSidebarCollapsedControl"]:hover,
[data-testid="stExpandSidebarButton"]:hover,
[data-testid="collapsedControl"]:hover {{
  border-color: rgba(245,165,36,.5) !important; background: rgba(26,34,49,.95) !important;
}}
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="stExpandSidebarButton"] svg,
[data-testid="collapsedControl"] svg {{ fill: {ACCENT} !important; color: {ACCENT} !important; }}

/* The matching collapse control inside the sidebar. */
[data-testid="stSidebarCollapseButton"] button,
[data-testid="stSidebarHeader"] button {{
  color: var(--muted) !important; opacity: .8;
}}
[data-testid="stSidebarCollapseButton"] button:hover {{ color: var(--accent) !important; opacity: 1; }}

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
  background: linear-gradient(180deg, #10161F 0%, #0D131C 100%);
  border-right: 1px solid rgba(255,255,255,.055);
  box-shadow: 1px 0 0 rgba(0,0,0,.4);
}}
[data-testid="stSidebar"] .block-container {{ padding: 1.1rem .85rem !important; }}

/* Streamlit's built-in page nav is disabled in config.toml (it painted before
   any script output and flashed unstyled on the login screen), so no rules for
   it are kept here — dead selectors for an element that never renders read as
   if the menu still exists. Everything in the sidebar is now our own content,
   in the order we emit it, so no reordering is needed either. */

/* Navigation is now built with st.page_link (see theme.sidebar_nav) because
   the built-in menu is disabled in config.toml — it painted before any script
   output and flashed unstyled on the login screen. */
[data-testid="stSidebar"] [data-testid="stPageLink"] a,
[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"] {{
  border-radius: 9px; padding: .44rem .6rem !important; gap: .62rem;
  color: #97A3B8 !important; font-size: .875rem !important; font-weight: 500 !important;
  border: 1px solid transparent; margin: 1px 0;
  transition: background .14s ease, color .14s ease, border-color .14s ease;
}}
[data-testid="stSidebar"] [data-testid="stPageLink"] a:hover,
[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"]:hover {{
  background: rgba(255,255,255,.05) !important; color: var(--text) !important;
}}
[data-testid="stSidebar"] [data-testid="stPageLink"] a[aria-current="page"],
[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"][aria-current="page"] {{
  background: linear-gradient(90deg, rgba(245,165,36,.15), rgba(245,165,36,.03)) !important;
  border-color: rgba(245,165,36,.28); color: var(--text) !important; font-weight: 600 !important;
}}
[data-testid="stSidebar"] [data-testid="stPageLink"] span[data-testid="stIconMaterial"] {{
  color: #7C8AA3; font-size: 1.05rem;
}}
[data-testid="stSidebar"] [data-testid="stPageLink"] a:hover span[data-testid="stIconMaterial"],
[data-testid="stSidebar"] [data-testid="stPageLink"] a[aria-current="page"] span[data-testid="stIconMaterial"] {{
  color: var(--accent);
}}

/* Sidebar sign-out sits at the foot, quieter than a primary action. */
[data-testid="stSidebar"] .stButton > button {{
  background: transparent; border: 1px solid rgba(255,255,255,.09); color: #97A3B8;
  font-weight: 500; font-size: .82rem; padding: .42rem .8rem;
}}
[data-testid="stSidebar"] .stButton > button:hover {{
  border-color: rgba(240,66,107,.45); color: #F0426B; background: rgba(240,66,107,.06);
  transform: none;
}}

/* ── Page header ──────────────────────────────────────────────────────── */
.hs-header {{ margin: 0 0 1.5rem; padding-bottom: 1.15rem; border-bottom: 1px solid rgba(255,255,255,.055); }}
.hs-header .hs-eyebrow {{
  display: inline-flex; align-items: center; gap: .45rem;
  font-size: .66rem; font-weight: 700; letter-spacing: .15em; text-transform: uppercase;
  color: var(--accent); margin-bottom: .5rem;
}}
.hs-header .hs-eyebrow::before {{
  content: ''; width: 14px; height: 2px; border-radius: 2px; background: var(--accent);
}}
.hs-header h1 {{ margin: 0 0 .34rem !important; font-size: 1.72rem !important; font-weight: 650 !important; }}
.hs-header .hs-sub {{ color: var(--muted); font-size: .875rem; max-width: 82ch; line-height: 1.6; }}

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
/* Tightened from the first pass: 2.1rem of margin plus a rule plus Streamlit's
   own element gap produced dead bands of empty screen between every block. */
.hs-section {{ margin: 1.45rem 0 .75rem; }}
.hs-section h2 {{
  margin: 0 !important; font-size: 1.02rem !important; font-weight: 650 !important;
  letter-spacing: -.01em; display: flex; align-items: center; gap: .5rem;
}}
.hs-section h2::before {{
  content: ''; width: 3px; height: 15px; border-radius: 2px;
  background: var(--accent); opacity: .8;
}}
.hs-section .hs-s-sub {{
  color: var(--muted); font-size: .82rem; margin: .3rem 0 0 .8rem;
  line-height: 1.55; max-width: 84ch;
}}
.hs-rule {{
  height: 1px; border: 0; margin: 1.5rem 0 0;
  background: linear-gradient(90deg, rgba(255,255,255,.075), rgba(255,255,255,.012) 65%, transparent);
}}

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

/* ── Bordered containers ──────────────────────────────────────────────── */
/* st.container(border=True) ships a flat 1px box that reads as a different
   material from every other panel. Styling it here means the alert queue and
   the AI report card inherit the surface automatically. */
[data-testid="stVerticalBlockBorderWrapper"] {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border) !important; border-radius: 12px;
  box-shadow: 0 14px 34px -24px rgba(0,0,0,.9);
  transition: border-color .15s ease;
}}
[data-testid="stVerticalBlockBorderWrapper"]:hover {{ border-color: rgba(255,255,255,.13) !important; }}

/* Expanders inside them (evidence payloads) should read as a quiet drawer. */
[data-testid="stExpander"] details {{
  border: 1px solid var(--border); border-radius: 9px; background: rgba(255,255,255,.018);
}}
[data-testid="stExpander"] summary {{ font-size: .8rem !important; color: var(--muted); }}
[data-testid="stExpander"] summary:hover {{ color: var(--accent); }}

/* ── Sub-section heading ──────────────────────────────────────────────── */
/* Below theme.section() in the hierarchy — for the two or three panels that
   sit inside one section. Replaces ad-hoc "##### Title" markdown, which
   inherited Streamlit's heading sizes and broke the type scale. */
.hs-sub-head {{
  font-size: .72rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase;
  color: #7C8AA3; margin: .2rem 0 .6rem;
}}

/* ── Facts card ───────────────────────────────────────────────────────── */
/* Label/value pairs. Previously faked with a two-column dataframe, which
   rendered a sortable grid with "Field"/"Value" headers around what is really
   a definition list. */
.hs-facts {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
  animation: hs-rise .38s cubic-bezier(.22,.61,.36,1) both;
}}
.hs-facts .hs-f-row {{
  display: flex; align-items: baseline; gap: 1rem; justify-content: space-between;
  padding: .58rem .95rem; border-bottom: 1px solid rgba(255,255,255,.045);
}}
.hs-facts .hs-f-row:last-child {{ border-bottom: 0; }}
.hs-facts .hs-f-key {{
  font-size: .72rem; font-weight: 600; letter-spacing: .07em; text-transform: uppercase;
  color: var(--muted); white-space: nowrap;
}}
.hs-facts .hs-f-val {{
  font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: .82rem;
  color: var(--text); text-align: right; word-break: break-word;
}}
.hs-facts .hs-f-val.hs-f-muted {{ color: #5F6B82; font-style: italic; }}

/* ── Charts ───────────────────────────────────────────────────────────── */
/* Plotly renders into a bare div, so without this a chart floats on the page
   background while every neighbouring panel sits on a card — the single
   biggest reason the analytics page read as a different app. */
[data-testid="stPlotlyChart"] {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border); border-radius: 12px;
  padding: .85rem .7rem .55rem; overflow: hidden;
  box-shadow: 0 14px 34px -22px rgba(0,0,0,.9);
  animation: hs-rise .38s cubic-bezier(.22,.61,.36,1) both;
}}
[data-testid="stPlotlyChart"] .modebar {{ display: none !important; }}

/* ── Composition bar ──────────────────────────────────────────────────── */
/* A segmented proportion bar. Replaces pie/donut charts, which convey nothing
   at one category (a 100% circle) and force angle comparison at several.
   A single bar reads correctly at any n, and costs no chart library. */
.hs-comp {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem;
  animation: hs-rise .38s cubic-bezier(.22,.61,.36,1) both;
}}
.hs-comp .hs-c-track {{
  display: flex; height: 12px; border-radius: 999px; overflow: hidden;
  background: rgba(255,255,255,.05); margin-bottom: .85rem;
}}
.hs-comp .hs-c-seg {{
  height: 100%; animation: hs-grow .55s cubic-bezier(.22,.61,.36,1) both;
  border-right: 1px solid rgba(11,15,23,.65);
}}
.hs-comp .hs-c-seg:last-child {{ border-right: 0; }}
.hs-comp .hs-c-legend {{ display: flex; flex-direction: column; gap: .42rem; }}
.hs-comp .hs-c-item {{
  display: flex; align-items: center; gap: .55rem; font-size: .82rem;
}}
.hs-comp .hs-c-dot {{
  width: 9px; height: 9px; border-radius: 3px; flex: none;
}}
.hs-comp .hs-c-name {{ color: var(--text); flex: 1; }}
.hs-comp .hs-c-num {{
  font-family: 'JetBrains Mono', ui-monospace, monospace; color: var(--text);
}}
.hs-comp .hs-c-pct {{
  font-family: 'JetBrains Mono', ui-monospace, monospace; color: var(--muted);
  font-size: .78rem; min-width: 3.4rem; text-align: right;
}}

/* ── Meter ────────────────────────────────────────────────────────────── */
/* A labelled 0-100 bar. Same visual language as the progress column in
   theme.table(), so a score reads identically wherever it appears — unlike a
   Plotly gauge, which imported a second chart aesthetic for one number. */
.hs-meter {{
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem;
  animation: hs-rise .38s cubic-bezier(.22,.61,.36,1) both;
}}
.hs-meter .hs-m-top {{
  display: flex; align-items: baseline; justify-content: space-between; margin-bottom: .55rem;
}}
.hs-meter .hs-m-label {{
  font-size: .72rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: var(--muted);
}}
.hs-meter .hs-m-value {{
  font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 1.4rem;
  font-weight: 500; color: var(--text);
}}
.hs-meter .hs-m-track {{
  height: 7px; border-radius: 999px; background: rgba(255,255,255,.06); overflow: hidden;
}}
.hs-meter .hs-m-fill {{
  height: 100%; border-radius: 999px; background: var(--tone, var(--accent));
  box-shadow: 0 0 12px -2px var(--tone, var(--accent));
  animation: hs-grow .6s cubic-bezier(.22,.61,.36,1) both;
}}
.hs-meter .hs-m-note {{ font-size: .76rem; color: var(--muted); margin-top: .55rem; line-height: 1.5; }}
@keyframes hs-grow {{ from {{ width: 0; }} }}

/* ── Data tables ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {{
  border: 1px solid rgba(255,255,255,.07); border-radius: 12px; overflow: hidden;
  background: rgba(19,26,39,.5);
  box-shadow: 0 14px 34px -22px rgba(0,0,0,.9);
}}
/* Monospace for the cells only — headers stay in the UI face so they read as
   labels rather than data. */
[data-testid="stDataFrame"] [role="gridcell"] {{
  font-family: 'JetBrains Mono', ui-monospace, monospace !important;
  font-size: .8rem !important;
}}
[data-testid="stDataFrame"] [role="columnheader"] {{
  font-family: 'Inter', sans-serif !important; font-size: .7rem !important;
  font-weight: 600 !important; letter-spacing: .07em; text-transform: uppercase;
  color: #7C8AA3 !important; background: rgba(255,255,255,.022) !important;
}}
[data-testid="stDataFrame"] [role="row"]:hover [role="gridcell"] {{
  background: rgba(255,255,255,.028) !important;
}}

/* ── KPI card polish ──────────────────────────────────────────────────── */
.hs-kpi {{ transition: transform .16s ease, border-color .16s ease; }}
.hs-kpi:hover {{ transform: translateY(-2px); border-color: rgba(255,255,255,.13); }}
.hs-kpi .hs-k-value.hs-k-word {{ font-size: 1.3rem; letter-spacing: .02em; font-weight: 600; }}

/* Inline status dot for word-valued KPIs (ONLINE / IDLE / STALE). */
.hs-dot {{
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  background: currentColor; margin-right: .5rem; vertical-align: middle;
  box-shadow: 0 0 0 3px color-mix(in srgb, currentColor 22%, transparent);
  animation: hs-pulse 2.4s ease-in-out infinite;
}}
@keyframes hs-pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: .45; }} }}

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

/* ── Ambient background ───────────────────────────────────────────────── */
/* Flat #000 reads as "unstyled", not "dark". Two very low-opacity radial
   washes give the ground depth, and a fine grid at ~2% opacity gives the eye
   something to register scale against. All CSS — no images, nothing to load. */
.stApp::before {{
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background:
    radial-gradient(900px 620px at 12% -8%, rgba(245,165,36,.09), transparent 62%),
    radial-gradient(820px 560px at 92% 108%, rgba(74,158,255,.07), transparent 60%),
    radial-gradient(1100px 720px at 50% 50%, rgba(255,255,255,.014), transparent 70%);
}}
.stApp::after {{
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image:
    linear-gradient(rgba(255,255,255,.021) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.021) 1px, transparent 1px);
  background-size: 46px 46px;
  mask-image: radial-gradient(circle at 50% 40%, #000 20%, transparent 78%);
  -webkit-mask-image: radial-gradient(circle at 50% 40%, #000 20%, transparent 78%);
}}
.block-container, [data-testid="stSidebar"] {{ position: relative; z-index: 1; }}

/* ── Login ────────────────────────────────────────────────────────────── */
.hs-auth {{ text-align: center; margin: 2.6rem 0 1.5rem; animation: hs-rise .5s cubic-bezier(.22,.61,.36,1) both; }}
.hs-auth .hs-mark {{
  width: 54px; height: 54px; margin: 0 auto .95rem; display: grid; place-items: center;
  border-radius: 15px; background: linear-gradient(150deg, rgba(245,165,36,.19), rgba(245,165,36,.05));
  border: 1px solid rgba(245,165,36,.34);
  box-shadow: 0 0 0 6px rgba(245,165,36,.045), 0 14px 34px -14px rgba(245,165,36,.5);
}}
.hs-auth .hs-mark svg {{ display: block; }}
.hs-auth h1 {{
  margin: 0 !important; font-size: 1.62rem !important; font-weight: 650 !important;
  letter-spacing: -.03em; color: var(--text);
}}
.hs-auth .hs-tag {{
  color: var(--muted); font-size: .84rem; margin-top: .34rem; letter-spacing: .002em;
}}

/* The form element itself is the card — Streamlit widgets cannot be wrapped in
   custom markup, so it is styled in place rather than nested inside a div. */
[data-testid="stForm"] {{
  background: rgba(19,26,39,.72);
  -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px);
  border: 1px solid rgba(255,255,255,.075) !important;
  border-radius: 16px !important; padding: 1.6rem 1.55rem 1.4rem !important;
  box-shadow: 0 26px 60px -24px rgba(0,0,0,.85), 0 0 0 1px rgba(255,255,255,.014) inset;
  position: relative; overflow: hidden;
  animation: hs-rise .5s cubic-bezier(.22,.61,.36,1) .06s both;
}}
/* Hairline of brand colour along the card's top edge. */
[data-testid="stForm"]::before {{
  content: ''; position: absolute; top: 0; left: 12%; right: 12%; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(245,165,36,.55), transparent);
}}
[data-testid="stForm"] label {{
  font-size: .74rem !important; font-weight: 600 !important; letter-spacing: .07em;
  text-transform: uppercase; color: var(--muted) !important;
}}
[data-testid="stForm"] .stTextInput input {{ padding: .62rem .8rem !important; font-size: .92rem !important; }}

/* Streamlit prints "Press Enter to submit form" inside the focused field,
   where it collides with the reveal-password button. */
[data-testid="InputInstructions"], [data-testid="stWidgetInstructions"] {{ display: none !important; }}

/* The reveal-password eye, toned down from Streamlit's default. */
[data-testid="stForm"] button[title="Show password text"],
[data-testid="stForm"] .stTextInput button {{
  background: transparent !important; border: none !important; color: var(--muted) !important;
}}
[data-testid="stForm"] .stTextInput button:hover {{ color: var(--accent) !important; }}

[data-testid="stForm"] .stButton > button,
[data-testid="stForm"] button[kind="primaryFormSubmit"],
[data-testid="stForm"] button[kind="secondaryFormSubmit"] {{
  margin-top: .5rem; border-radius: 9px; font-weight: 600; font-size: .9rem;
  padding: .58rem 1rem; letter-spacing: .01em;
  background: linear-gradient(180deg, #F7B23E, #E89312) !important;
  border: 1px solid rgba(245,165,36,.9) !important; color: #171104 !important;
  box-shadow: 0 10px 26px -12px rgba(245,165,36,.7);
  transition: transform .14s ease, box-shadow .14s ease, filter .14s ease;
}}
[data-testid="stForm"] button[kind="primaryFormSubmit"]:hover {{
  filter: brightness(1.05); transform: translateY(-1px);
  box-shadow: 0 14px 30px -12px rgba(245,165,36,.8);
}}
[data-testid="stForm"] button[kind="primaryFormSubmit"]:active {{ transform: translateY(0); }}

.hs-auth-foot {{
  text-align: center; color: #5F6B82; font-size: .74rem; margin-top: 1.15rem;
  letter-spacing: .04em;
}}

/* While a rerun is in flight, Streamlit stamps data-stale="true" on each
   element container and dims it rather than removing it. For ordinary reruns
   that is the right behaviour — dimmed previous data beats a blank page. For
   the SIGN-IN transition it is not: the old login card hangs, greyed, on top
   of the dashboard that is loading behind it, which reads as a rendering bug.
   Only the auth elements are hidden outright; every other page keeps
   Streamlit's normal dimming. */
[data-testid="stElementContainer"][data-stale="true"]:has([data-testid="stForm"]),
[data-testid="stElementContainer"][data-stale="true"]:has(.hs-auth),
[data-testid="stElementContainer"][data-stale="true"]:has(.hs-auth-foot) {{
  display: none !important;
}}

/* Stale content elsewhere fades rather than sitting at full strength, so a
   refresh reads as "updating" instead of "frozen". */
[data-testid="stElementContainer"][data-stale="true"] {{
  opacity: .38; transition: opacity .12s ease;
}}
</style>
"""

# Inline so it needs no network fetch and inherits currentColor. A hex mark
# reads as "shield" without the childishness of an emoji at 54px.
LOGO_SVG = (
    '<svg width="26" height="28" viewBox="0 0 26 28" fill="none" '
    'xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
    '<path d="M13 1.6 24 7.6v12.8L13 26.4 2 20.4V7.6z" stroke="#F5A524" '
    'stroke-width="1.7" stroke-linejoin="round" fill="rgba(245,165,36,.10)"/>'
    '<path d="M13 8.2 18.6 11.4v6.2L13 20.8 7.4 17.6v-6.2z" fill="#F5A524" '
    'fill-opacity=".92"/></svg>'
)


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


NAV = [
    ("app.py", "Overview", ":material/dashboard:"),
    ("pages/01_🔴_Live_Feed.py", "Live Feed", ":material/sensors:"),
    ("pages/02_🌍_Attacker_Intel.py", "Attacker Intel", ":material/public:"),
    ("pages/03_📈_Analytics.py", "Analytics", ":material/insights:"),
    ("pages/04_🚨_Alerts.py", "Alerts", ":material/notifications_active:"),
    ("pages/05_🔍_Threat_Hunting.py", "Threat Hunting", ":material/search:"),
    ("pages/06_🎪_Campaigns.py", "Campaigns", ":material/hub:"),
    ("pages/07_🤖_AI_Analysis.py", "AI Analysis", ":material/smart_toy:"),
]


def sidebar_nav() -> None:
    """
    Navigation, rendered only for authenticated sessions.

    Replaces Streamlit's built-in page menu, which is disabled in config.toml
    because the frontend paints it before any script output arrives — meaning
    it flashed, unstyled, on the login screen no matter what CSS was injected.
    Material icons replace the filename emoji, which rendered as clip art.

    st.page_link cannot resolve page routes under Streamlit's AppTest harness
    (it raises KeyError('url_pathname') with no page context), so failures are
    swallowed: a test harness losing its nav is not worth an exception on a
    page that otherwise renders correctly.
    """
    st.sidebar.markdown(
        f'<div style="font-size:.63rem;font-weight:700;letter-spacing:.16em;'
        f'color:#5C6883;padding:.15rem .1rem .45rem">NAVIGATION</div>',
        unsafe_allow_html=True,
    )
    for target, label, icon in NAV:
        try:
            st.sidebar.page_link(target, label=label, icon=icon)
        except Exception:  # noqa: BLE001 — see docstring
            pass


def auth_brand(title: str, tagline: str) -> None:
    """
    Brand block for the sign-in screen.

    Lives here rather than in login.py because composing the logo SVG into
    markup requires interpolation, and only this module is permitted to
    interpolate into a raw-HTML sink (see the security note at the top, and the
    check in tests/test_dashboard_security.py). Arguments are escaped.
    """
    st.markdown(
        f'<div class="hs-auth"><div class="hs-mark">{LOGO_SVG}</div>'
        f"<h1>{esc(title)}</h1>"
        f'<div class="hs-tag">{esc(tagline)}</div></div>',
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
        # A word-valued KPI (ONLINE, MEDIUM) set at the numeric size looks like
        # a headline rather than a reading; it gets its own scale plus a live
        # status dot in the tone colour.
        word = not str(it["value"]).replace(",", "").replace("/", "").replace("%", "").isdigit()
        dot = f'<span class="hs-dot" style="color:{esc(tone)}"></span>' if word and it.get("dot") else ""
        value_class = "hs-k-value hs-k-word" if word else "hs-k-value"
        cards.append(
            f'<div class="hs-kpi" style="--tone:{esc(tone)}">'
            f'<div class="hs-k-label">{esc(it["label"])}</div>'
            f'<div class="{value_class}">{dot}{esc(it["value"])}</div>{note}</div>'
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


def subsection(title: str) -> None:
    """A heading one level below section(), for panels inside a section."""
    st.markdown(f'<div class="hs-sub-head">{esc(title)}</div>', unsafe_allow_html=True)


def badge(text: str, level: Optional[str] = None, detail: str = "") -> None:
    """
    A severity pill, optionally followed by a plain-text detail.

    Replaces the coloured-circle emoji (🔴🟠🟡🔵) used for severity: those are
    clip art at text size, carry no relationship to the palette every other
    element uses, and are invisible to anyone who reads by colour name rather
    than glyph. The pill takes its colour from SEVERITY, so a MEDIUM alert is
    the same amber here as in a table, a meter and a composition bar.
    """
    tone = severity_tone(level or text)
    extra = (f'<span style="color:{MUTED};font-size:.86rem;margin-left:.6rem">'
             f"{esc(detail)}</span>") if detail else ""
    st.markdown(
        f'<div style="margin:.1rem 0 .35rem">'
        f'<span class="hs-badge" style="color:{esc(tone)}">{esc(text)}</span>{extra}</div>',
        unsafe_allow_html=True,
    )


def facts(items: dict) -> None:
    """
    A label/value card — a definition list, not a table.

    Values are escaped, so this is safe for enrichment data. It is NOT the
    place for attacker-supplied text: those belong in table(), where cells are
    inert by construction rather than by remembering to escape.
    """
    rows = []
    for key, value in items.items():
        empty = value in (None, "", "unknown")
        shown = "not available" if empty else value
        cls = "hs-f-val hs-f-muted" if empty else "hs-f-val"
        rows.append(
            f'<div class="hs-f-row"><span class="hs-f-key">{esc(key)}</span>'
            f'<span class="{cls}">{esc(shown)}</span></div>'
        )
    st.markdown(f'<div class="hs-facts">{"".join(rows)}</div>', unsafe_allow_html=True)


def composition(segments: Sequence[dict]) -> None:
    """
    A segmented proportion bar with a legend.

    Each segment: {"label": str, "value": int|float, "color": str}.

    Preferred over a pie or donut. At one category a donut is a filled circle
    conveying nothing; at several, angles are harder to compare than lengths.
    A stacked bar plus explicit counts and percentages answers "how much of
    each" directly, and stays legible when one category dominates — which is
    the normal case here, since only HTTP is deployed.
    """
    total = sum(float(s["value"]) for s in segments) or 1.0
    bar, legend = [], []
    for seg in segments:
        pct = float(seg["value"]) / total * 100
        color = seg.get("color", ACCENT)
        bar.append(f'<div class="hs-c-seg" style="width:{pct:.2f}%;background:{esc(color)}"></div>')
        legend.append(
            f'<div class="hs-c-item">'
            f'<span class="hs-c-dot" style="background:{esc(color)}"></span>'
            f'<span class="hs-c-name">{esc(seg["label"])}</span>'
            f'<span class="hs-c-num">{esc(seg["value"])}</span>'
            f'<span class="hs-c-pct">{pct:.1f}%</span></div>'
        )
    st.markdown(
        f'<div class="hs-comp"><div class="hs-c-track">{"".join(bar)}</div>'
        f'<div class="hs-c-legend">{"".join(legend)}</div></div>',
        unsafe_allow_html=True,
    )


def meter(label: str, value: Optional[float], maximum: float = 100,
          tone: Optional[str] = None, note: str = "") -> None:
    """
    A labelled 0-100 bar, matching the progress column used inside table().

    `value=None` renders an explicit "not measured" state rather than a zero
    bar, because "no data" and "scored zero" mean very different things for a
    reputation score.
    """
    if value is None:
        st.markdown(
            f'<div class="hs-meter"><div class="hs-m-top">'
            f'<span class="hs-m-label">{esc(label)}</span>'
            f'<span class="hs-m-value" style="color:#5F6B82">—</span></div>'
            f'<div class="hs-m-track"></div>'
            f'<div class="hs-m-note">{esc(note or "Not checked yet.")}</div></div>',
            unsafe_allow_html=True,
        )
        return

    pct = max(0.0, min(100.0, (float(value) / maximum) * 100))
    tone = tone or ACCENT
    note_html = f'<div class="hs-m-note">{esc(note)}</div>' if note else ""
    st.markdown(
        f'<div class="hs-meter" style="--tone:{esc(tone)}"><div class="hs-m-top">'
        f'<span class="hs-m-label">{esc(label)}</span>'
        f'<span class="hs-m-value">{esc(value)}<span style="font-size:.85rem;'
        f'color:{MUTED}">/{esc(int(maximum))}</span></span></div>'
        f'<div class="hs-m-track"><div class="hs-m-fill" style="width:{pct:.1f}%"></div></div>'
        f"{note_html}</div>",
        unsafe_allow_html=True,
    )


# Human labels and display types for every column these pages render. Raw
# `snake_case` headers and full ISO timestamps are how a database looks, not
# how a console should read — and `threat_score` as a bare integer wastes the
# one column where a reader most wants to compare magnitudes at a glance.
_COLUMNS = {
    "connected_at":      ("Time", "datetime", "small"),
    "filtered_at":       ("Time", "datetime", "small"),
    "attempted_at":      ("Time", "datetime", "small"),
    "created_at":        ("Raised", "datetime", "small"),
    "generated_at":      ("Generated", "datetime", "small"),
    "first_seen":        ("First seen", "datetime", "small"),
    "last_seen":         ("Last seen", "datetime", "small"),
    "campaign_start":    ("Started", "datetime", "small"),
    "campaign_end":      ("Ended", "datetime", "small"),
    "ip_address":        ("Source IP", "text", "medium"),
    "peer_ip":           ("Peer IP", "text", "medium"),
    "country":           ("Country", "text", "small"),
    "city":              ("City", "text", "small"),
    "isp":               ("Network", "text", "medium"),
    "asn":               ("ASN", "text", "medium"),
    "method":            ("Method", "text", "small"),
    "path":              ("Path", "text", "medium"),
    "user_agent":        ("User agent", "text", "large"),
    "service":           ("Service", "text", "small"),
    "port":              ("Port", "int", "small"),
    "threat_score":      ("Threat", "score", "small"),
    "verdict":           ("Verdict", "text", "small"),
    "severity":          ("Severity", "text", "small"),
    "alert_type":        ("Detection", "text", "medium"),
    "total_connections": ("Sessions", "int", "small"),
    "attacker_count":    ("Attackers", "int", "small"),
    "abuseipdb_score":   ("AbuseIPDB", "int", "small"),
    "otx_pulse_count":   ("OTX", "int", "small"),
    "username":          ("Username", "text", "medium"),
    "password":          ("Password", "text", "medium"),
    "hits":              ("Hits", "int", "small"),
    "value":             ("Value", "text", "medium"),
    "attempts":          ("Attempts", "int", "small"),
    "sources":           ("Sources", "int", "small"),
    "cnt":               ("Count", "int", "small"),
    "id":                ("ID", "int", "small"),
    "connection_id":     ("Conn", "int", "small"),
    "evidence":          ("Evidence", "text", "large"),
    "acknowledged":      ("Ack", "bool", "small"),
}


def table(df, columns: Optional[Sequence[str]] = None, height: Optional[int] = None) -> None:
    """
    Render a dataframe with human column labels and sensible display types.

    Still `st.dataframe`, which treats every cell as inert text — this changes
    only presentation, never the rendering guarantee that lets attacker-supplied
    values (paths, User-Agents, captured credentials) be shown at all.

    `columns` selects and orders; unknown columns fall through with their raw
    name rather than being dropped, so a new field shows up rather than
    silently disappearing.
    """
    if columns:
        df = df[[c for c in columns if c in df.columns]]

    config = {}
    for col in df.columns:
        label, kind, width = _COLUMNS.get(col, (col.replace("_", " ").title(), "text", None))
        if kind == "datetime":
            config[col] = st.column_config.DatetimeColumn(label, format="D MMM HH:mm", width=width)
        elif kind == "score":
            # A progress bar makes 5 vs 20 vs 85 comparable at a glance in a way
            # the integer alone does not.
            config[col] = st.column_config.ProgressColumn(
                label, format="%d", min_value=0, max_value=100, width=width
            )
        elif kind == "int":
            config[col] = st.column_config.NumberColumn(label, format="%d", width=width)
        elif kind == "bool":
            config[col] = st.column_config.CheckboxColumn(label, width=width)
        else:
            config[col] = st.column_config.TextColumn(label, width=width)

    st.dataframe(df, width="stretch", hide_index=True, column_config=config,
                 **({"height": height} if height else {}))


CHART_SEQUENCE = [ACCENT, "#4A9EFF", "#3DD68C", "#F0426B", "#A78BFA", "#FF7A45"]


def style_chart(fig, height: int = 320):
    """
    Apply the console's visual language to a Plotly figure.

    Centralised deliberately: charts previously configured fonts, gridlines and
    hover styling at each call site, so a palette change had to be repeated per
    chart and drifted between them.
    """
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=MUTED, size=12),
        margin=dict(l=8, r=8, t=18, b=8),
        xaxis=dict(gridcolor="rgba(255,255,255,.045)", zerolinecolor="rgba(255,255,255,.07)",
                   linecolor="rgba(255,255,255,.07)", tickfont=dict(size=11)),
        yaxis=dict(gridcolor="rgba(255,255,255,.045)", zerolinecolor="rgba(255,255,255,.07)",
                   linecolor="rgba(255,255,255,.07)", tickfont=dict(size=11)),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=MUTED, size=11)),
        colorway=CHART_SEQUENCE,
        # Tooltips inherited Plotly's light default, which flared white on a
        # dark console every time the pointer crossed a series.
        hoverlabel=dict(bgcolor=SURFACE_2, bordercolor=BORDER,
                        font=dict(family="JetBrains Mono, monospace", color=TEXT, size=12)),
        hovermode="closest",
    )
    return fig


def plot(fig, height: int = 320) -> None:
    """
    Style and render a figure. Use this instead of st.plotly_chart directly, so
    the modebar suppression and sizing stay in one place.
    """
    st.plotly_chart(style_chart(fig, height), width="stretch",
                    config={"displayModeBar": False, "staticPlot": False})


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
