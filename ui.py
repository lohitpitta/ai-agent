import streamlit as st
import subprocess
import sys
import re
from pathlib import Path
 
# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------
 
st.set_page_config(
    page_title="DepGuard AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)
 
# --------------------------------------------------
# STYLES  (light, flat, one accent colour)
# --------------------------------------------------
 
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700&display=swap');
 
    :root {
        --bg: #f6f7f9;
        --surface: #ffffff;
        --text: #1f2933;
        --muted: #667085;
        --border: #e1e5ea;
        --accent: #2b5c8a;
        --accent-dark: #224a70;
        --ok: #1a7f4b;
        --warn: #b54708;
        --bad: #b42318;
    }
 
    html, body, [class*="css"], .stApp {
        font-family: 'Public Sans', system-ui, sans-serif;
    }
 
    .stApp, [data-testid="stAppViewContainer"] {
        background-color: var(--bg);
        color: var(--text);
    }
 
    [data-testid="stHeader"] {
        background: transparent;
    }
 
    #MainMenu, footer {
        visibility: hidden;
    }
 
    .block-container {
        max-width: 780px;
        padding-top: 3rem;
        padding-bottom: 4rem;
    }
 
    [data-testid="stSidebar"] {
        background-color: var(--surface);
        border-right: 1px solid var(--border);
    }
 
    /* ---------- text ---------- */
 
    h1, h2, h3, h4, p, label, span, li {
        color: var(--text);
    }
 
    .app-title {
        font-size: 28px;
        font-weight: 700;
        color: var(--text);
        margin: 0;
    }
 
    .app-sub {
        color: var(--muted);
        font-size: 15px;
        margin: 4px 0 28px 0;
    }
 
    .section-title {
        font-size: 17px;
        font-weight: 600;
        color: var(--text);
        margin: 32px 0 12px 0;
    }
 
    /* ---------- input ---------- */
 
    div[data-baseweb="input"] {
        background-color: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
    }
 
    div[data-baseweb="input"]:focus-within {
        border-color: var(--accent);
    }
 
    div[data-baseweb="input"] input {
        color: var(--text);
        background-color: var(--surface);
    }
 
    [data-testid="stTextInput"] label p {
        font-weight: 500;
        font-size: 14px;
        color: var(--text);
    }
 
    /* ---------- buttons ---------- */
 
    div.stButton > button[kind="primary"],
    div.stDownloadButton > button {
        background-color: var(--accent);
        color: #ffffff;
        border: 1px solid var(--accent);
        border-radius: 6px;
        font-weight: 600;
        padding: 0.55rem 1.4rem;
        box-shadow: none;
    }
 
    div.stButton > button[kind="primary"] p,
    div.stDownloadButton > button p {
        color: #ffffff;
    }
 
    div.stButton > button[kind="primary"]:hover,
    div.stDownloadButton > button:hover {
        background-color: var(--accent-dark);
        border-color: var(--accent-dark);
        color: #ffffff;
    }
 
    /* ---------- results ---------- */
 
    .stats {
        display: flex;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
    }
 
    .stat {
        flex: 1;
        padding: 18px 22px;
        border-right: 1px solid var(--border);
    }
 
    .stat:last-child {
        border-right: none;
    }
 
    .stat-value {
        font-size: 30px;
        font-weight: 700;
        line-height: 1.1;
        color: var(--text);
    }
 
    .stat-value.bad  { color: var(--bad); }
    .stat-value.warn { color: var(--warn); }
    .stat-value.ok   { color: var(--ok); }
 
    .stat-label {
        font-size: 13px;
        color: var(--muted);
        margin-top: 6px;
    }
 
    .status {
        margin-top: 14px;
        padding: 12px 16px;
        border-radius: 6px;
        font-size: 14px;
        border: 1px solid var(--border);
        background: var(--surface);
        border-left-width: 4px;
    }
 
    .status.ok   { border-left-color: var(--ok); }
    .status.warn { border-left-color: var(--warn); }
    .status.bad  { border-left-color: var(--bad); }
 
    .status .meta {
        color: var(--muted);
        font-size: 13px;
        margin-top: 2px;
    }
 
    .steps {
        display: flex;
        gap: 32px;
        margin-top: 8px;
    }
 
    .steps div {
        flex: 1;
        font-size: 14px;
        color: var(--muted);
        line-height: 1.5;
    }
 
    .steps strong {
        display: block;
        color: var(--text);
        font-weight: 600;
        margin-bottom: 2px;
    }
 
    @media (max-width: 640px) {
        .stats, .steps { flex-direction: column; gap: 0; }
        .stat { border-right: none; border-bottom: 1px solid var(--border); }
        .stat:last-child { border-bottom: none; }
        .steps { gap: 14px; }
    }
 
    /* ---------- misc ---------- */
 
    [data-testid="stExpander"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
    }
 
    [data-testid="stExpander"] summary p {
        color: var(--text);
        font-weight: 500;
    }
 
    hr {
        border-color: var(--border);
    }
</style>
""", unsafe_allow_html=True)
 
 
# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------
 
def extract_number(pattern, text, default=0):
    match = re.search(pattern, text, re.IGNORECASE)
 
    if match:
        return int(match.group(1))
 
    return default
 
 
def stat_html(value, label, tone=""):
    return (
        f'<div class="stat">'
        f'<div class="stat-value {tone}">{value}</div>'
        f'<div class="stat-label">{label}</div>'
        f'</div>'
    )
 
 
# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------
 
if "scan_output" not in st.session_state:
    st.session_state.scan_output = ""
 
if "scan_success" not in st.session_state:
    st.session_state.scan_success = False
 
if "report_path" not in st.session_state:
    st.session_state.report_path = None
 
if "scan_id" not in st.session_state:
    st.session_state.scan_id = None
 
 
# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
 
with st.sidebar:
    st.markdown("### DepGuard AI")
    st.caption(
        "Scans a local project for known dependency "
        "vulnerabilities and creates an HTML report."
    )
 
 
# --------------------------------------------------
# HEADER
# --------------------------------------------------
 
st.markdown('<p class="app-title">🛡️ DepGuard AI</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="app-sub">Check your project\'s dependencies for known vulnerabilities.</p>',
    unsafe_allow_html=True
)
 
 
# --------------------------------------------------
# PROJECT INPUT
# --------------------------------------------------
 
project_path = st.text_input(
    "Project folder path",
    placeholder=r"D:\AI AGENT\AI AGENT\test-project",
    help="Enter the full path of the project you want to scan."
)
 
start_scan = st.button("Start scan", type="primary")
 
 
# --------------------------------------------------
# RUN SCAN
# --------------------------------------------------
 
if start_scan:
 
    if not project_path.strip():
        st.error("Enter the project folder path to start a scan.")
 
    else:
        project = Path(project_path.strip().strip('"'))
        app_path = Path(__file__).resolve().parent / "app.py"
 
        if not project.is_dir():
            st.error("This folder doesn't exist. Check the path and try again.")
 
        elif not app_path.is_file():
            st.error("Could not find app.py in the application folder.")
 
        else:
            with st.spinner("Scanning dependencies and checking vulnerabilities..."):
                try:
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(app_path),
                            "scan",
                            str(project.resolve())
                        ],
                        capture_output=True,
                        text=True,
                        timeout=600,
                        cwd=str(app_path.parent)
                    )
 
                    output = result.stdout or ""
                    errors = result.stderr or ""
 
                    st.session_state.scan_output = output
 
                    id_match = re.search(
                        r"Scan ID:\s*(\S+)",
                        output,
                        re.IGNORECASE
                    )
 
                    st.session_state.scan_id = (
                        id_match.group(1) if id_match else None
                    )
 
                    report_match = re.search(
                        r"Report generated:\s*(.+?\.html)",
                        output,
                        re.IGNORECASE
                    )
 
                    st.session_state.report_path = None
 
                    if report_match:
                        raw_report_path = report_match.group(1).strip()
                        report_path = Path(raw_report_path)
 
                        if not report_path.is_absolute():
                            report_path = app_path.parent / report_path
 
                        if report_path.is_file():
                            st.session_state.report_path = report_path.resolve()
 
                    st.session_state.scan_success = (
                        result.returncode == 0
                    )
 
                    if result.returncode != 0:
                        st.error("The scan failed. Details are below.")
 
                        if errors:
                            st.code(errors)
 
                except subprocess.TimeoutExpired:
                    st.session_state.scan_success = False
                    st.error("The scan took longer than 10 minutes and was stopped.")
 
                except Exception as error:
                    st.session_state.scan_success = False
                    st.error(f"Unexpected error: {error}")
 
 
# --------------------------------------------------
# RESULTS
# --------------------------------------------------
 
if st.session_state.scan_success:
 
    output = st.session_state.scan_output
 
    st.markdown('<div class="section-title">Results</div>', unsafe_allow_html=True)
 
    total_dependencies = extract_number(
        r"Extracted\s+(\d+)\s+dependencies",
        output
    )
 
    confirmed_vulnerabilities = extract_number(
        r"Confirmed Vulnerabilities:\s*(\d+)",
        output
    )
 
    ambiguous_findings = extract_number(
        r"Ambiguous:\s*(\d+)",
        output
    )
 
    scan_id = st.session_state.scan_id or "Unavailable"
 
    vuln_tone = "bad" if confirmed_vulnerabilities > 0 else "ok"
    amb_tone = "warn" if ambiguous_findings > 0 else ""
 
    st.markdown(
        '<div class="stats">'
        + stat_html(total_dependencies, "Dependencies")
        + stat_html(confirmed_vulnerabilities, "Confirmed vulnerabilities", vuln_tone)
        + stat_html(ambiguous_findings, "Need review", amb_tone)
        + '</div>',
        unsafe_allow_html=True
    )
 
    if confirmed_vulnerabilities > 0:
        status_tone = "bad"
        status_text = "Vulnerabilities found"
    elif ambiguous_findings > 0:
        status_tone = "warn"
        status_text = "No confirmed vulnerabilities, some findings need review"
    else:
        status_tone = "ok"
        status_text = "No vulnerabilities found"
 
    st.markdown(
        f"""
        <div class="status {status_tone}">
            <strong>{status_text}</strong>
            <div class="meta">Scan ID: {scan_id}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
 
    # ---------- report ----------
 
    st.markdown('<div class="section-title">Report</div>', unsafe_allow_html=True)
 
    report_path = st.session_state.report_path
 
    if report_path and report_path.is_file():
 
        try:
            report_html = report_path.read_text(encoding="utf-8")
 
            st.download_button(
                label="Download HTML report",
                data=report_html,
                file_name=report_path.name,
                mime="text/html"
            )
 
            st.caption(f"Saved at: {report_path}")
 
        except Exception as error:
            st.warning(f"Could not read the report file: {error}")
 
    else:
        st.info(
            "The scan finished, but the report file could not be found. "
            "Check the scan output below."
        )
 
 
# --------------------------------------------------
# SCAN OUTPUT
# --------------------------------------------------
 
if st.session_state.scan_output:
 
    st.markdown("<br>", unsafe_allow_html=True)
 
    with st.expander("Scan output"):
        st.code(st.session_state.scan_output, language="text")
 
 
# --------------------------------------------------
# INITIAL STATE
# --------------------------------------------------
 
if not st.session_state.scan_output:
 
    st.markdown('<div class="section-title">How it works</div>', unsafe_allow_html=True)
 
    st.markdown(
        """
        <div class="steps">
            <div><strong>Choose a project</strong>Enter the folder path of your local project.</div>
            <div><strong>Run the scan</strong>Dependencies are checked against known vulnerability data.</div>
            <div><strong>Read the report</strong>Download the HTML report and review the findings.</div>
        </div>
        """,
        unsafe_allow_html=True
    )