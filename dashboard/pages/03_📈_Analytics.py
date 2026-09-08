"""
Analytics — aggregate views over captured traffic.

All values are counts computed in SQL; nothing here renders attacker text.
"""

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import data, theme
from dashboard.login import require_auth

st.set_page_config(page_title="HoneyShield — Analytics", page_icon="📈", layout="wide")
require_auth("📈", "Analytics")

theme.page_header(
    "",
    "Analytics",
    "Volume, composition and severity of captured traffic over time. Counts are "
    "computed in the database, so nothing here is sampled or estimated.",
    eyebrow="Aggregates",
)

with st.sidebar:
    st.markdown("**Analytics controls**")
    hours = st.slider("Timeline window (hours)", 1, 168, 24)

_d = data.analytics(hours)
timeline, services, verdicts, top = _d["timeline"], _d["services"], _d["verdicts"], _d["top"]

# ── Headline numbers ──────────────────────────────────────────────────────
# The page previously opened straight onto a chart, with no summary of what the
# window contained — so a flat line and an empty window looked the same.
window_total = sum(row["cnt"] for row in timeline) if timeline else 0
busiest = max(timeline, key=lambda r: r["cnt"]) if timeline else None
service_total = sum(row["cnt"] for row in services) if services else 0
risky = sum(row["cnt"] for row in verdicts
            if str(row.get("verdict", "")).upper() in ("HIGH", "CRITICAL")) if verdicts else 0

theme.kpis([
    {"label": "In window", "value": window_total,
     "note": f"connections in {hours}h", "tone": theme.ACCENT},
    {"label": "Busiest bucket", "note": "peak activity", "tone": "#4A9EFF",
     "value": f"{busiest['cnt']}" if busiest else "—"},
    {"label": "Sources ranked", "value": len(top), "note": "by session volume",
     "tone": theme.MUTED},
    {"label": "High or critical", "value": risky, "note": "scored attackers",
     "tone": theme.SEVERITY["HIGH"] if risky else theme.MUTED},
])

# ── Timeline ──────────────────────────────────────────────────────────────
theme.section("Connections over time",
              f"Captured sessions per bucket across the last {hours} hour(s).")

if timeline:
    # The query groups by hour and returns ONLY hours that had connections, so
    # quiet hours are absent rather than zero. Plotly then sizes each bar from
    # the spacing between the points it was given: two hits 9 hours apart drew
    # two 9-hour-wide blocks, reading as sustained traffic when the truth was
    # two isolated requests. Reindexing onto a complete hourly range restores
    # the real shape — one narrow bar per hour, zeros in between.
    df = pd.DataFrame(timeline)
    df["bucket"] = pd.to_datetime(df["bucket"], utc=True)
    end = pd.Timestamp.now(tz="UTC").ceil("h")
    full = pd.date_range(end=end, periods=hours + 1, freq="h")
    df = (df.set_index("bucket")["cnt"]
            .reindex(full, fill_value=0)
            .rename_axis("bucket").reset_index(name="cnt"))

    fig = px.bar(df, x="bucket", y="cnt", labels={"bucket": "", "cnt": ""})
    fig.update_traces(
        marker=dict(color=theme.ACCENT, line=dict(width=0)),
        # One hour wide, stated in milliseconds, so a bar means exactly its
        # bucket rather than whatever gap happens to sit beside it.
        width=3600 * 1000 * 0.8,
        hovertemplate="%{x|%d %b %H:%M}<br><b>%{y}</b> connection(s)<extra></extra>",
    )
    peak = int(df["cnt"].max())
    fig.update_layout(
        bargap=0,
        yaxis=dict(rangemode="tozero", tickformat="d",
                   dtick=1 if peak <= 6 else None, range=[0, max(1, peak) * 1.15],
                   title=dict(text="connections", font=dict(size=11))),
        # Pin the axis to the window that was actually asked for. Auto-ranging
        # to the data made a 24h window render a ~36h span.
        xaxis=dict(showgrid=False, range=[full[0], full[-1]], tickformat="%d %b\n%H:%M"),
    )
    theme.plot(fig, height=280)
    st.caption(
        "Gaps are expected: on a free PaaS tier the service sleeps after ~15 minutes "
        "idle, so a flat stretch means nobody called during that window — not that "
        "capture stopped. Sensor health on the Overview page distinguishes the two."
    )
else:
    theme.empty_state(
        "📉",
        f"Nothing captured in the last {hours}h",
        "Widen the window in the sidebar, or wait for traffic. This host is "
        "unadvertised, so arrivals are sporadic automated scanners rather than a "
        "steady stream.",
    )

# ── Composition ───────────────────────────────────────────────────────────
theme.section(
    "Composition",
    f"Both panels cover the same {hours}-hour window as the timeline above, but "
    f"they count different things — sessions on the left, distinct attackers on "
    f"the right — so the totals are not meant to match.",
)

left, right = st.columns(2, gap="medium")

with left:
    theme.subsection("Sessions by service")
    if services:
        # A donut of one category is a filled circle conveying nothing, and
        # only HTTP is deployed — so the common case for this panel is exactly
        # the case a pie handles worst. A proportion bar reads correctly at any
        # number of categories and shows the counts outright.
        theme.composition([
            {"label": str(row["service"]).upper(), "value": row["cnt"],
             "color": theme.CHART_SEQUENCE[i % len(theme.CHART_SEQUENCE)]}
            for i, row in enumerate(sorted(services, key=lambda r: -r["cnt"]))
        ])
        st.caption(
            f"All {service_total} session(s) in this window are HTTP — the only "
            "service exposed on this deployment. SSH, FTP and Telnet are built and "
            "tested but deliberately not deployed."
            if len(services) == 1 else
            f"{service_total} session(s) across the exposed honeypot services."
        )
    else:
        theme.empty_state("🧩", "No service data",
                          "No connections have been captured yet, so there is nothing "
                          "to break down.")

with right:
    theme.subsection("Attackers by verdict")
    if verdicts:
        # Ordered by severity rather than by count, so the axis reads as a
        # scale. Plotly sorts categories by first appearance otherwise, which
        # put CRITICAL next to LOW depending on which arrived first.
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        by_verdict = {str(r["verdict"]).upper(): r["cnt"] for r in verdicts}
        theme.composition([
            {"label": v.title(), "value": by_verdict.get(v, 0),
             "color": theme.SEVERITY[v]}
            for v in order if by_verdict.get(v, 0)
        ])
        st.caption(
            f"{sum(by_verdict.values())} attacker(s) active in this window, by "
            "verdict. Derived from the weighted threat score: LOW below 25, "
            "MEDIUM to 50, HIGH to 80, CRITICAL above.")
    else:
        theme.empty_state("⚖️", "No scored attackers",
                          "Scoring runs the moment an IP is captured and enriched.")

# ── Volume leaders ────────────────────────────────────────────────────────
theme.section(
    "Most active sources",
    "Ranked by each source's ALL-TIME session count, not the window above — "
    "total_connections is a lifetime counter on the attacker record. Volume alone "
    "is not severity: a noisy scanner can outrank a targeted probe.")

if top:
    adf = pd.DataFrame(top).sort_values("total_connections", ascending=True)
    # Discrete verdict colours, not a continuous scale: a colourbar spends a
    # legend on a value already shown in the tooltip, and four named severity
    # bands are what the operator actually reasons about.
    adf["verdict"] = adf["verdict"].fillna("UNSCORED").str.upper()
    fig = px.bar(
        adf, x="total_connections", y="ip_address", orientation="h",
        color="verdict",
        color_discrete_map={**theme.SEVERITY, "UNSCORED": theme.MUTED},
        category_orders={"verdict": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED"]},
        custom_data=["country", "verdict", "threat_score"],
        labels={"total_connections": "", "ip_address": ""},
        text="total_connections",
    )
    fig.update_traces(
        marker=dict(line=dict(width=0)),
        textposition="outside",
        textfont=dict(family="JetBrains Mono, monospace", size=11, color=theme.MUTED),
        cliponaxis=False,
        hovertemplate=("<b>%{y}</b><br>%{x} session(s)<br>"
                       "%{customdata[0]} · %{customdata[1]} · "
                       "score %{customdata[2]}/100<extra></extra>"),
    )
    fig.update_layout(
        bargap=.42,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
        xaxis=dict(showgrid=True, rangemode="tozero", tickformat="d", dtick=1,
                   range=[0, max(adf["total_connections"]) * 1.18]),
        yaxis=dict(showgrid=False,
                   tickfont=dict(family="JetBrains Mono, monospace", size=11)),
    )
    theme.plot(fig, height=max(230, 44 * len(adf) + 60))
    st.caption("Bars are coloured by verdict, so a long green bar reads as noisy "
               "scanning while a short amber or red one is worth opening. Volume "
               "alone is not severity.")
else:
    theme.empty_state("🏷️", "No sources yet",
                      "Nothing has reached the honeypot, so there is no volume to rank.")
