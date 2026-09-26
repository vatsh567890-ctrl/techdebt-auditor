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
    call_ai_for_explanation, call_ai_for_repo_summary, call_ai_for_file_review,
    set_watsonx_credentials, scan_backlog_iter,
    PROFILES, PROFILE_DEFAULT, get_fixes_for,
)
from github_issues import create_issues

# set_page_config MUST be the first Streamlit call
st.set_page_config(
    page_title="Tech Debt & Security Auditor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── All styles in one block ────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Animated gradient page background ─────────────────────────────────── */
    .stApp {
        background: linear-gradient(-45deg, #0f0c29, #302b63, #24243e, #0f0c29);
        background-size: 400% 400%;
        animation: gradientShift 15s ease infinite;
    }
    @keyframes gradientShift {
        0%   { background-position: 0%   50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0%   50%; }
    }

    /* ── Layout container ───────────────────────────────────────────────────── */
    .block-container {
        padding-top: 2.5rem !important;   /* fix: was 0, caused title clip */
        padding-bottom: 2rem;
        max-width: 1100px !important;     /* wider to let the 3-col grid breathe */
        margin-left: auto !important;
        margin-right: auto !important;
    }

    /* ── Flashy title / subtitle ────────────────────────────────────────────── */
    p.flashy-title {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00f2fe, #4facfe, #a78bfa, #00f2fe);
        background-size: 300% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        animation: shimmer 4s linear infinite;
        text-align: center;
        margin: 1.5rem 0 0;
        line-height: 1.15;
    }
    @keyframes shimmer {
        to { background-position: 300% center; }
    }
    p.flashy-subtitle {
        text-align: center;
        color: #b8c1ec;
        font-size: 1.05rem;
        margin-top: 0.4rem;
        margin-bottom: 2rem;
        line-height: 1.55;
    }

    /* ── Glassmorphic input card ────────────────────────────────────────────── */
    .glass-card {
        background: rgba(255, 255, 255, 0.06);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 16px;
        padding: 1.5rem 1.5rem 1rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        margin-bottom: 1.5rem;
    }
    .glass-card-label {
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        opacity: 0.55;
        margin-bottom: 0.4rem;
    }

    /* ── Glowing button ─────────────────────────────────────────────────────── */
    .stButton > button {
        background: linear-gradient(90deg, #4facfe, #00f2fe) !important;
        color: #0f0c29 !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.6rem 1.5rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 0 15px rgba(79, 172, 254, 0.4) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) scale(1.03) !important;
        box-shadow: 0 0 25px rgba(79, 172, 254, 0.8) !important;
    }

    /* ── Severity badge spans ───────────────────────────────────────────────── */
    span.badge-high {
        display: inline-block;
        background: rgba(255, 71, 87, 0.15);
        color: #ff4757;
        border: 1px solid #ff4757;
        padding: 3px 11px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.82rem;
        animation: pulseRed 1.5s infinite;
        vertical-align: middle;
    }
    @keyframes pulseRed {
        0%, 100% { box-shadow: 0 0 5px  rgba(255, 71, 87, 0.5); }
        50%       { box-shadow: 0 0 18px rgba(255, 71, 87, 0.9); }
    }
    span.badge-medium {
        display: inline-block;
        background: rgba(255, 165, 2, 0.15);
        color: #ffa502;
        border: 1px solid #ffa502;
        padding: 3px 11px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.82rem;
        vertical-align: middle;
    }
    span.badge-low {
        display: inline-block;
        background: rgba(46, 213, 115, 0.15);
        color: #2ed573;
        border: 1px solid #2ed573;
        padding: 3px 11px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.82rem;
        vertical-align: middle;
    }

    /* ── Metric cards ───────────────────────────────────────────────────────── */
    div[data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 1rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
        transition: transform 0.2s ease;
    }
    div[data-testid="stMetric"]:hover { transform: translateY(-4px); }

    [data-testid="metric-container"] {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 1rem 1.25rem;
    }
    [data-testid="metric-container"] [data-testid="stMetricLabel"] {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.6;
    }
    .metric-card { border-radius: 10px; padding: 1rem 1.25rem; height: 100%; }
    .metric-card .mc-label {
        font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.07em; opacity: 0.75; margin-bottom: 0.3rem;
    }
    .metric-card .mc-value { font-size: 2rem; font-weight: 800; line-height: 1.1; }
    .mc-high   { background: rgba(220, 38,  38,  0.18); border: 1px solid rgba(220, 38,  38,  0.35); color: #fca5a5; }
    .mc-medium { background: rgba(217, 119,  6,   0.18); border: 1px solid rgba(217, 119,  6,   0.35); color: #fcd34d; }
    .mc-low    { background: rgba( 22, 163, 74,   0.18); border: 1px solid rgba( 22, 163, 74,   0.35); color: #86efac; }
    .mc-total  { background: rgba( 45, 212, 191,  0.12); border: 1px solid rgba( 45, 212, 191,  0.30); color: #5eead4; }

    /* ── Responsive backlog grid ────────────────────────────────────────────── */
    .backlog-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin: 1rem 0 1.5rem;
    }
    @media (max-width: 900px) {
        .backlog-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 560px) {
        .backlog-grid { grid-template-columns: 1fr; }
    }

    /* Individual grid card */
    .bl-card {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        padding: 1rem 1.1rem 0.9rem;
        display: flex;
        flex-direction: column;
        gap: 0.45rem;
        animation: fadeInUp 0.35s ease both;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .bl-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 24px rgba(0,0,0,0.35);
    }
    .bl-card.sev-high   { border-left: 4px solid #ff4757; }
    .bl-card.sev-medium { border-left: 4px solid #ffa502; }
    .bl-card.sev-low    { border-left: 4px solid #2ed573; }

    .bl-card-file {
        font-size: 0.78rem;
        font-family: 'SFMono-Regular', Consolas, monospace;
        color: #a5b4fc;
        word-break: break-all;
        line-height: 1.35;
    }
    .bl-card-score {
        font-size: 1.6rem;
        font-weight: 800;
        line-height: 1;
        color: #f1f5f9;
    }
    .bl-card-meta {
        font-size: 0.75rem;
        color: rgba(255,255,255,0.5);
        margin-top: 0.1rem;
    }
    .bl-card-effort {
        font-size: 0.78rem;
        font-weight: 600;
        color: #94a3b8;
        margin-top: auto;
        padding-top: 0.4rem;
        border-top: 1px solid rgba(255,255,255,0.07);
    }

    /* Stagger fade-in on grid cards */
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(14px); }
        to   { opacity: 1; transform: translateY(0);    }
    }
    .bl-card:nth-child(1)  { animation-delay: 0.00s; }
    .bl-card:nth-child(2)  { animation-delay: 0.05s; }
    .bl-card:nth-child(3)  { animation-delay: 0.10s; }
    .bl-card:nth-child(4)  { animation-delay: 0.15s; }
    .bl-card:nth-child(5)  { animation-delay: 0.20s; }
    .bl-card:nth-child(6)  { animation-delay: 0.25s; }
    .bl-card:nth-child(n+7){ animation-delay: 0.30s; }

    /* Left-border severity stripe on detail expander rows */
    [data-testid="stExpander"]:has(.badge-high)   { border-left: 4px solid #ff4757; border-radius: 6px; margin-bottom: 4px; }
    [data-testid="stExpander"]:has(.badge-medium) { border-left: 4px solid #ffa502; border-radius: 6px; margin-bottom: 4px; }
    [data-testid="stExpander"]:has(.badge-low)    { border-left: 4px solid #2ed573; border-radius: 6px; margin-bottom: 4px; }

    /* ── Expander body / download button ────────────────────────────────────── */
    [data-testid="stExpander"] > div:last-child { padding: 0.75rem 1rem; }
    [data-testid="stDownloadButton"] button {
        border: 1px solid rgba(255,255,255,0.12);
        background: rgba(255,255,255,0.06);
        font-size: 0.85rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar ────────────────────────────────────────────────────────────────────
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

# ── (1) Flashy title + subtitle ───────────────────────────────────────────────
st.markdown(
    "<p class='flashy-title'>🔍 Tech Debt &amp; Security Auditor</p>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p class='flashy-subtitle'>"
    "Point this at a GitHub repo and get a ranked <strong>fix-this-first</strong> backlog "
    "— scored on complexity, staleness, test coverage, and risky patterns."
    "</p>",
    unsafe_allow_html=True,
)

# ── (2) Glass-card input area ──────────────────────────────────────────────────
# Bug fix: combine opening tag + label into ONE st.markdown call so Streamlit
# doesn't insert an empty container div between the glass-card border and label.
st.markdown(
    "<div class='glass-card'><div class='glass-card-label'>GitHub repo URL</div>",
    unsafe_allow_html=True,
)
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
            # Persist so the render loop can re-read file content for AI reviews
            st.session_state["_local_path"] = local_path
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

    page_count = min(len(filtered), 50)
    st.caption(f"Showing {page_count} of {len(filtered)} files")

    # ── Responsive 3-col grid — pure HTML summary cards ───────────────────────
    # Each card shows: badge, file path, score, effort, LOC. No interactivity
    # here — all interactive detail (fixes, AI review) stays in expanders below.
    grid_parts = []
    for item in filtered[:page_count]:
        score = item["risk_score"]
        if score >= 70:
            badge_html = "<span class='badge-high'>🔴 HIGH</span>"
            sev_cls    = "sev-high"
        elif score >= 40:
            badge_html = "<span class='badge-medium'>🟠 MEDIUM</span>"
            sev_cls    = "sev-medium"
        else:
            badge_html = "<span class='badge-low'>🟢 LOW</span>"
            sev_cls    = "sev-low"

        # Escape angle-brackets in file paths (shouldn't exist but be safe)
        safe_file = item["file"].replace("<", "&lt;").replace(">", "&gt;")
        grid_parts.append(
            f"<div class='bl-card {sev_cls}'>"
            f"  <div>{badge_html}</div>"
            f"  <div class='bl-card-file'>{safe_file}</div>"
            f"  <div class='bl-card-score'>{score}<span style='font-size:0.9rem;opacity:.5;font-weight:400'>/100</span></div>"
            f"  <div class='bl-card-meta'>📏 {item['line_count']:,} lines &nbsp;·&nbsp; 🕐 {item['staleness_days']}d ago</div>"
            f"  <div class='bl-card-effort'>⏱ {item['effort_estimate']}</div>"
            f"</div>"
        )
    st.markdown(
        "<div class='backlog-grid'>" + "".join(grid_parts) + "</div>",
        unsafe_allow_html=True,
    )

    # ── Detail expanders (one per file, collapsed by default) ─────────────────
    st.markdown(
        "<div style='font-size:0.82rem;opacity:0.5;margin:0.25rem 0 0.75rem'>"
        "▼ Click any file below for detailed findings, fixes, and AI review"
        "</div>",
        unsafe_allow_html=True,
    )
    for item in filtered[:page_count]:
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
            # Styled badge span + file path inside body (HTML works here)
            st.markdown(
                f"{badge_html}&ensp;"
                f"<code style='font-size:.9em'>{item['file']}</code>"
                f"&ensp;<span style='opacity:.45;font-size:.82em'>score {score} / 100</span>",
                unsafe_allow_html=True,
            )
            st.markdown("")

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

            # ── How to Fix This ───────────────────────────────────────────────
            fixes = get_fixes_for(item["risky_findings"])
            if fixes:
                with st.expander("🔧 How to Fix This", expanded=False):
                    for finding, fix_text in fixes:
                        short_label = finding.split(" -- ")[0]
                        st.markdown(
                            f"<div style='"
                            f"border-left:3px solid #2dd4bf;"
                            f"padding:0.55rem 0.85rem;"
                            f"margin-bottom:0.65rem;"
                            f"border-radius:0 6px 6px 0;"
                            f"background:rgba(45,212,191,0.07)'>"
                            f"<div style='font-size:0.78rem;font-weight:700;"
                            f"text-transform:uppercase;letter-spacing:0.05em;"
                            f"opacity:0.7;margin-bottom:0.25rem'>{short_label}</div>"
                            f"{fix_text}"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

            # ── AI Review & Suggested Fix ─────────────────────────────────────
            repo_path = st.session_state.get("_local_path", "")
            _review_key = f"_ai_review_{item['file']}"
            with st.expander("🤖 AI Review & Suggested Fix", expanded=False):
                if _review_key not in st.session_state:
                    if repo_path:
                        with st.spinner("Generating AI review…"):
                            st.session_state[_review_key] = call_ai_for_file_review(
                                repo_path, item
                            )
                    else:
                        st.session_state[_review_key] = {
                            "review": "_Source path unavailable — re-run the scan to enable AI reviews._",
                            "fix": "", "lang": "", "error": None,
                        }

                result = st.session_state[_review_key]

                if result.get("error"):
                    st.warning(f"⚠️ AI call failed: {result['error']}")

                if result.get("review"):
                    st.markdown("**Review**")
                    st.markdown(result["review"])

                if result.get("fix"):
                    st.markdown("**Suggested fix**")
                    lang = result.get("lang") or "text"
                    st.code(result["fix"], language=lang)
                elif not result.get("error"):
                    st.caption(
                        "_No AI credentials configured — add your watsonx API key in the "
                        "sidebar to get a concrete code fix here._"
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
