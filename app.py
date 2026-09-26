"""
app.py
------
The visual dashboard. This is what judges will actually see and click
around in during your demo.

Run this with:  streamlit run app.py
"""

import csv
import io
from pathlib import Path as _Path

import streamlit as st
from analyzer import (
    build_backlog, clone_repo, extract_zip,
    call_ai_for_explanation, call_ai_for_repo_summary,
    set_watsonx_credentials, scan_backlog_iter,
    PROFILES, PROFILE_DEFAULT,
)
from github_issues import create_issues

st.set_page_config(
    page_title="Tech Debt & Security Auditor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global styles ──────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── 1. Max-width container — centres content, kills edge-to-edge stretch */
    .block-container {
        padding-top: 0 !important;
        padding-bottom: 2rem;
        max-width: 860px !important;
        margin-left: auto !important;
        margin-right: auto !important;
    }

    /* ── 2. Input+button card ───────────────────────────────────────────────── */
    .input-card {
        background: var(--secondary-background-color, #1e293b);
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 12px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.35);
        padding: 1.25rem 1.5rem 1rem;
        margin-bottom: 1.5rem;
    }
    .input-card-label {
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        opacity: 0.55;
        margin-bottom: 0.4rem;
    }

    /* ── 3. Metric cards — generic fallback (Total files card) ─────────────── */
    [data-testid="metric-container"] {
        background: var(--secondary-background-color, #1e293b);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 1rem 1.25rem;
    }
    [data-testid="metric-container"] [data-testid="stMetricLabel"] {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.6;
    }

    /* ── 3b. Coloured severity metric cards ─────────────────────────────────── */
    .metric-card {
        border-radius: 10px;
        padding: 1rem 1.25rem;
        height: 100%;
    }
    .metric-card .mc-label {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        opacity: 0.75;
        margin-bottom: 0.3rem;
    }
    .metric-card .mc-value {
        font-size: 2rem;
        font-weight: 800;
        line-height: 1.1;
    }
    .mc-high   { background: rgba(220, 38,  38,  0.18); border: 1px solid rgba(220, 38,  38,  0.35); color: #fca5a5; }
    .mc-medium { background: rgba(217, 119, 6,   0.18); border: 1px solid rgba(217, 119, 6,   0.35); color: #fcd34d; }
    .mc-low    { background: rgba( 22, 163, 74,  0.18); border: 1px solid rgba( 22, 163, 74,  0.35); color: #86efac; }
    .mc-total  { background: rgba( 45, 212, 191, 0.12); border: 1px solid rgba( 45, 212, 191, 0.30); color: #5eead4; }

    /* ── 4. Severity badge pills ────────────────────────────────────────────── */
    .badge {
        display: inline-block;
        padding: 0.18em 0.65em;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        vertical-align: middle;
    }
    .badge-high   { background: #dc2626; color: #fff; }
    .badge-medium { background: #d97706; color: #fff; }
    .badge-low    { background: #16a34a; color: #fff; }

    /* Left-border severity stripe on expander rows */
    [data-testid="stExpander"]:has(.badge-high)   { border-left: 4px solid #dc2626; border-radius: 6px; margin-bottom: 4px; }
    [data-testid="stExpander"]:has(.badge-medium) { border-left: 4px solid #d97706; border-radius: 6px; margin-bottom: 4px; }
    [data-testid="stExpander"]:has(.badge-low)    { border-left: 4px solid #16a34a; border-radius: 6px; margin-bottom: 4px; }

    /* ── 5. Expander body / download button ─────────────────────────────────── */
    [data-testid="stExpander"] > div:last-child { padding: 0.75rem 1rem; }

    [data-testid="stDownloadButton"] button {
        border: 1px solid rgba(255,255,255,0.12);
        background: var(--secondary-background-color, #1e293b);
        font-size: 0.85rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar: watsonx credentials ───────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🤖 watsonx.ai — AI Explanations")
    st.caption(
        "Optional. When provided, every backlog item gets a one-sentence "
        "AI-generated explanation from IBM Granite instead of the rule-based summary."
    )
    wx_api_key    = st.text_input("IBM Cloud API key",  type="password", placeholder="…")
    wx_project_id = st.text_input("watsonx Project ID", placeholder="xxxxxxxx-xxxx-…")
    wx_url        = st.text_input(
        "watsonx.ai URL",
        value="https://us-south.ml.cloud.ibm.com",
        placeholder="https://us-south.ml.cloud.ibm.com",
    )
    if wx_api_key and wx_project_id:
        set_watsonx_credentials(wx_api_key, wx_project_id, wx_url)
        st.success("Credentials saved — AI explanations enabled.", icon="✅")
    else:
        st.info("Enter credentials above to enable AI explanations.", icon="ℹ️")

# ── Header banner ──────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="
        background: linear-gradient(135deg, #134e4a 0%, #0f766e 60%, #2dd4bf 100%);
        border-radius: 14px;
        padding: 2rem 2.25rem 1.75rem;
        margin-bottom: 1.75rem;
        margin-top: 1.25rem;
    ">
      <div style="font-size:1.75rem;font-weight:800;color:#fff;letter-spacing:-0.02em;line-height:1.2;">
        🔍 Tech Debt &amp; Security Auditor
      </div>
      <div style="margin-top:0.5rem;font-size:0.95rem;color:rgba(255,255,255,0.78);line-height:1.55;max-width:560px;">
        Point this at a GitHub repo and get a ranked <strong style="color:#fff;">fix-this-first</strong>
        backlog — scored on complexity, staleness, test coverage, and risky patterns.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Input card ─────────────────────────────────────────────────────────────────
st.markdown("<div class='input-card'>", unsafe_allow_html=True)
st.markdown("<div class='input-card-label'>GitHub repo URL</div>", unsafe_allow_html=True)
col_url, col_btn = st.columns([5, 1])
with col_url:
    repo_url = st.text_input(
        "GitHub repo URL",
        placeholder="https://github.com/some-org/some-repo",
        label_visibility="collapsed",
    )
with col_btn:
    st.markdown("<div style='padding-top:1.75rem'>", unsafe_allow_html=True)
    run_button = st.button("▶  Analyze", type="primary", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)

# ── Analysis ───────────────────────────────────────────────────────────────────
if run_button and not repo_url:
    st.warning("Paste a GitHub repo URL first.")

if run_button and repo_url:
    with st.spinner("Cloning repo and scanning files… this can take a minute for larger repos"):
        try:
            local_path = clone_repo(repo_url)
            backlog = build_backlog(local_path)
        except Exception as e:
            st.error(f"Something went wrong: {e}")
            backlog = []

    if not backlog:
        st.warning("No code files found, or the repo failed to clone. Double-check the URL.")
        st.stop()

    high_risk   = [b for b in backlog if b["risk_score"] >= 70]
    medium_risk = [b for b in backlog if 40 <= b["risk_score"] < 70]
    low_risk    = [b for b in backlog if b["risk_score"] < 40]

    # ── Summary bar ────────────────────────────────────────────────────────────
    st.success(f"Scanned **{len(backlog)}** code files.")

    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(
        f"<div class='metric-card mc-total'>"
        f"<div class='mc-label'>🔍 Total files</div>"
        f"<div class='mc-value'>{len(backlog)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    m2.markdown(
        f"<div class='metric-card mc-high'>"
        f"<div class='mc-label'>🔴 High risk</div>"
        f"<div class='mc-value'>{len(high_risk)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    m3.markdown(
        f"<div class='metric-card mc-medium'>"
        f"<div class='mc-label'>🟠 Medium risk</div>"
        f"<div class='mc-value'>{len(medium_risk)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    m4.markdown(
        f"<div class='metric-card mc-low'>"
        f"<div class='mc-label'>🟢 Low risk</div>"
        f"<div class='mc-value'>{len(low_risk)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # ── Risk distribution chart ────────────────────────────────────────────────
    st.markdown("#### Risk distribution")
    chart_data = {
        "Risk level": ["High (≥70)", "Medium (40–69)", "Low (<40)"],
        "Files":      [len(high_risk), len(medium_risk), len(low_risk)],
    }
    bar_cols = st.columns([2, 1])
    with bar_cols[0]:
        st.bar_chart(
            data={"High": [len(high_risk)], "Medium": [len(medium_risk)], "Low": [len(low_risk)]},
            height=180,
            use_container_width=True,
        )

    # ── Create GitHub Issues ───────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### 🐛 Create GitHub Issues")
    st.caption("Auto-files an issue for each of the top 5 highest-risk files in the scanned repo.")

    gh_col_token, gh_col_btn = st.columns([4, 1])
    with gh_col_token:
        gh_token = st.text_input(
            "GitHub Personal Access Token (needs `repo` scope)",
            type="password",
            placeholder="ghp_…",
            label_visibility="visible",
        )
    with gh_col_btn:
        st.write("")  # vertical alignment
        st.write("")
        create_issues_btn = st.button(
            "📋 Create Issues", use_container_width=True, disabled=not gh_token
        )

    if create_issues_btn and gh_token:
        top5 = backlog[:5]
        with st.spinner(f"Creating {len(top5)} issue(s) on GitHub…"):
            results = create_issues(repo_url, gh_token, top5)

        for r in results:
            if r["status"] == "created":
                st.success(f"✅ [{r['file']}]({r['issue_url']}) — issue created")
            else:
                st.error(f"❌ {r['file']} — {r['error']}")

    # ── Export ─────────────────────────────────────────────────────────────────
    csv_buffer = io.StringIO()
    fieldnames = ["file", "risk_score", "effort_estimate", "line_count",
                  "staleness_days", "has_test", "risky_findings"]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for item in backlog:
        writer.writerow({**item, "risky_findings": "; ".join(item.get("risky_findings") or [])})

    st.markdown("---")
    hdr_left, hdr_right = st.columns([3, 1])
    with hdr_left:
        st.markdown("#### Prioritized backlog")
    with hdr_right:
        st.download_button(
            label="⬇ Export CSV",
            data=csv_buffer.getvalue(),
            file_name="techdebt_backlog.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # ── Filter controls ────────────────────────────────────────────────────────
    # Derive folder and extension option lists from the full backlog
    def _top_folder(file_path: str) -> str:
        parts = _Path(file_path).parts
        return parts[0] if len(parts) > 1 else "(root)"

    all_folders = sorted({_top_folder(b["file"]) for b in backlog})
    all_exts    = sorted({_Path(b["file"]).suffix or "(none)" for b in backlog})

    filter_col, folder_col, ext_col, sort_col = st.columns([2, 2, 2, 2])
    with filter_col:
        risk_filter = st.multiselect(
            "Risk level",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
        )
    with folder_col:
        folder_filter = st.multiselect(
            "Folder",
            options=all_folders,
            default=all_folders,
            placeholder="All folders",
        )
    with ext_col:
        ext_filter = st.multiselect(
            "File type",
            options=all_exts,
            default=all_exts,
            placeholder="All types",
        )
    with sort_col:
        sort_order = st.selectbox(
            "Sort by",
            options=["Risk score (highest first)", "Risk score (lowest first)", "File name"],
        )

    # Apply filters
    level_map = {
        "High":   lambda b: b["risk_score"] >= 70,
        "Medium": lambda b: 40 <= b["risk_score"] < 70,
        "Low":    lambda b: b["risk_score"] < 40,
    }
    filtered = [
        b for b in backlog
        if any(level_map[l](b) for l in risk_filter)
        and _top_folder(b["file"]) in folder_filter
        and (_Path(b["file"]).suffix or "(none)") in ext_filter
    ]

    # Apply sort
    if sort_order == "Risk score (lowest first)":
        filtered = sorted(filtered, key=lambda b: b["risk_score"])
    elif sort_order == "File name":
        filtered = sorted(filtered, key=lambda b: b["file"])
    # default is already sorted highest-first from build_backlog

    st.caption(f"Showing {min(len(filtered), 50)} of {len(filtered)} files")

    # ── Backlog items ──────────────────────────────────────────────────────────
    for item in filtered[:50]:
        score = item["risk_score"]
        if score >= 70:
            badge_html = "<span class='badge-high'>🔴 HIGH</span>"
            badge_txt  = "🔴 HIGH"
        elif score >= 40:
            badge_html = "<span class='badge-medium'>🟠 MEDIUM</span>"
            badge_txt  = "🟠 MEDIUM"
        else:
            badge_html = "<span class='badge-low'>🟢 LOW</span>"
            badge_txt  = "🟢 LOW"

        with st.expander(f"{badge_txt}  ·  {item['file']}   (score: {score})"):
            info_a, info_b = st.columns(2)
            with info_a:
                st.markdown(f"**Effort estimate:** {item['effort_estimate']}")
                st.markdown(f"**Lines of code:** {item['line_count']:,}")
            with info_b:
                st.markdown(f"**Days since last change:** {item['staleness_days']}")
                has_test_icon = "✅ Yes" if item["has_test"] else "❌ No"
                st.markdown(f"**Has a matching test file:** {has_test_icon}")

            if item["risky_findings"]:
                st.markdown("**Why this is flagged:**")
                for reason in item["risky_findings"]:
                    st.markdown(f"- {reason}")
            else:
                st.markdown(
                    "_No specific risky pattern — flagged for general complexity / staleness._"
                )

            explanation = call_ai_for_explanation("", item)
            st.info(f"💡 {explanation}")

# ── Footer ─────────────────────────────────────────────────────────────────────
st.markdown(
    "<hr style='margin-top:2.5rem;opacity:0.15'>",
    unsafe_allow_html=True,
)
st.caption(
    "Scoring = 30 % complexity · 25 % staleness · 25 % missing tests · 20 % risky patterns  "
    "·  Built for enterprises managing large legacy codebases."
)