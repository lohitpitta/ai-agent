from __future__ import annotations

import html
import hmac
import os
import re
import subprocess
import sys
import sqlite3
import hashlib
import secrets
from pathlib import Path
from typing import Optional

import streamlit as st
import streamlit.components.v1 as components

# Keep this file (ui.py) beside the existing CLI scanner: app.py
st.set_page_config(
    page_title="DepGuard AI | Dependency Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

THEMES = {
    "Dark": {
        "bg": "#0b1120", "surface": "#111a2e", "surface_alt": "#17233a",
        "text": "#e8eef8", "muted": "#9aa9c0", "border": "#263650",
        "accent": "#65a8ff", "accent_hover": "#3e8df5", "good": "#4bd4a0",
        "warn": "#f6bd60", "bad": "#ff737e", "shadow": "rgba(0,0,0,.16)",
    },
    "Light": {
        "bg": "#f4f7fb", "surface": "#ffffff", "surface_alt": "#edf3fa",
        "text": "#162235", "muted": "#62718a", "border": "#dce5f0",
        "accent": "#245fbd", "accent_hover": "#174b9b", "good": "#13865e",
        "warn": "#a76508", "bad": "#c43e4b", "shadow": "rgba(22,34,53,.06)",
    },
}

if "theme" not in st.session_state:
    st.session_state.theme = "Dark"
if "scan_output" not in st.session_state:
    st.session_state.scan_output = ""
if "scan_errors" not in st.session_state:
    st.session_state.scan_errors = ""
if "scan_success" not in st.session_state:
    st.session_state.scan_success = False
if "scan_returncode" not in st.session_state:
    st.session_state.scan_returncode = None
if "report_path" not in st.session_state:
    st.session_state.report_path = None
if "scan_id" not in st.session_state:
    st.session_state.scan_id = None
if "scanned_project" not in st.session_state:
    st.session_state.scanned_project = ""
if "scan_duration_note" not in st.session_state:
    st.session_state.scan_duration_note = ""

C = THEMES[st.session_state.theme]

st.markdown(
    f"""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
      :root {{
        --bg:{C['bg']}; --surface:{C['surface']}; --surface-alt:{C['surface_alt']};
        --text:{C['text']}; --muted:{C['muted']}; --border:{C['border']};
        --accent:{C['accent']}; --accent-hover:{C['accent_hover']};
        --good:{C['good']}; --warn:{C['warn']}; --bad:{C['bad']};
      }}
      html, body, [class*="css"], .stApp {{ font-family: Inter, system-ui, sans-serif; }}
      .stApp, [data-testid="stAppViewContainer"] {{ background:var(--bg); color:var(--text); }}
      [data-testid="stHeader"] {{ background:transparent; }}
      [data-testid="stSidebar"] {{ background:var(--surface); border-right:1px solid var(--border); }}
      [data-testid="stSidebar"] * {{ color:var(--text); }}
      .block-container {{ max-width:1500px; padding-top:1.7rem; padding-bottom:3rem; }}
      h1,h2,h3,h4,p,label,span,li {{ color:var(--text); }}
      [data-testid="stCaptionContainer"] p, .muted {{ color:var(--muted) !important; }}
      .hero {{ display:flex; align-items:center; justify-content:space-between; gap:1rem;
        padding:1.4rem 1.6rem; border:1px solid var(--border); border-radius:18px;
        background:linear-gradient(120deg,var(--surface),var(--surface-alt)); margin-bottom:1.25rem; }}
      .brandline {{ display:flex; align-items:center; gap:14px; }}
      .brandicon {{ display:flex; align-items:center; justify-content:center; width:52px; height:52px;
        border-radius:15px; background:var(--accent); color:white; font-size:26px; }}
      .hero-title {{ font-size:clamp(1.45rem,2.5vw,2rem); font-weight:800; letter-spacing:-.04em; margin:0; }}
      .hero-sub {{ color:var(--muted); margin:.3rem 0 0 0; font-size:.93rem; }}
      .eyebrow {{ text-transform:uppercase; font-size:.72rem; letter-spacing:.12em; font-weight:700; color:var(--accent); }}
      .panel {{ border:1px solid var(--border); border-radius:15px; background:var(--surface); padding:1.1rem 1.2rem; }}
      .panel-title {{ font-size:1rem; font-weight:700; margin:0 0 .25rem 0; }}
      .panel-sub {{ color:var(--muted); font-size:.84rem; margin:0 0 .85rem 0; }}
      .metric-card {{ background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.05rem 1.15rem; min-height:116px; box-shadow:0 4px 18px {C['shadow']}; }}
      .metric-label {{ color:var(--muted); font-size:.82rem; font-weight:600; }}
      .metric-value {{ font-size:2rem; font-weight:800; letter-spacing:-.04em; line-height:1.3; margin-top:.3rem; }}
      .metric-foot {{ color:var(--muted); font-size:.75rem; margin-top:.15rem; }}
      .pill {{ display:inline-block; padding:.3rem .65rem; border-radius:999px; font-size:.76rem; font-weight:700; border:1px solid var(--border); }}
      .pill-good {{ color:var(--good); }} .pill-warn {{ color:var(--warn); }} .pill-bad {{ color:var(--bad); }}
      .step-card {{ border:1px solid var(--border); background:var(--surface); padding:1rem; border-radius:13px; min-height:115px; }}
      .step-number {{ color:var(--accent); font-size:.75rem; font-weight:800; letter-spacing:.1em; }}
      .step-title {{ font-weight:700; margin:.35rem 0 .2rem; }}
      .step-desc {{ color:var(--muted); font-size:.82rem; line-height:1.5; }}
      div[data-baseweb="input"] {{ background:var(--surface); border-radius:10px; border-color:var(--border); }}
      div[data-baseweb="input"] input {{ color:var(--text); }}
      div.stButton>button, div.stDownloadButton>button {{ border-radius:10px; font-weight:700; min-height:2.7rem; }}
      div.stButton>button[kind="primary"], div.stDownloadButton>button {{ background:var(--accent); color:#fff; border-color:var(--accent); }}
      div.stButton>button[kind="primary"]:hover, div.stDownloadButton>button:hover {{ background:var(--accent-hover); border-color:var(--accent-hover); color:#fff; }}
      div.stButton>button[kind="primary"] p, div.stDownloadButton>button p {{ color:#fff; }}
      [data-testid="stTabs"] button {{ font-weight:650; }}
      [data-testid="stExpander"] {{ border:1px solid var(--border); border-radius:12px; background:var(--surface); }}
      hr {{ border-color:var(--border); }}
      code {{ color:var(--accent) !important; }}
      .login-wrap {{ max-width:520px; margin:5vh auto 0 auto; }}
      .login-card {{ border:1px solid var(--border); border-radius:20px; padding:2rem; background:var(--surface); box-shadow:0 18px 50px {C['shadow']}; }}
      .login-brand {{ display:flex; align-items:center; gap:14px; margin-bottom:1.5rem; }}
      .login-icon {{ display:flex; align-items:center; justify-content:center; width:56px; height:56px; border-radius:16px; background:#ffc83b; color:#1a1a1a; font-size:28px; }}
      .login-title {{ font-size:1.8rem; font-weight:800; letter-spacing:-.04em; margin:0; }}
      .login-subtitle {{ color:var(--muted); margin:.25rem 0 1.25rem; }}
      .auth-banner {{ border:1px solid var(--border); border-radius:22px; overflow:hidden; background:linear-gradient(135deg,#e6eaef 0%,#fff5d6 100%); padding:2rem; min-height:100%; color:#1a1a1a; }}
      .auth-banner h2 {{ color:#1a1a1a !important; font-size:1.8rem; letter-spacing:-.04em; margin:.8rem 0 .5rem; }}
      .auth-banner p {{ color:#58616d !important; line-height:1.6; }}
      .auth-chip {{ display:inline-block; border-radius:999px; padding:.35rem .7rem; background:#fff; color:#333; font-size:.75rem; font-weight:700; border:1px solid #e0e3e8; }}
      .auth-stat {{ background:rgba(255,255,255,.82); border:1px solid rgba(0,0,0,.06); border-radius:13px; padding:1rem; margin-top:.75rem; }}
      .auth-stat-label {{ color:#667085; font-size:.78rem; }}
      .auth-stat-value {{ color:#1a1a1a; font-size:1.45rem; font-weight:800; margin-top:.25rem; }}
      div[data-testid="stTextInput"] input {{ border-radius:999px; }}
      div.stButton>button[kind="primary"], div[data-testid="stFormSubmitButton"] button[kind="primary"] {{ background:#ffc83b; color:#1a1a1a; border-color:#ffc83b; border-radius:999px; font-weight:750; }}
      div.stButton>button[kind="primary"] p, div[data-testid="stFormSubmitButton"] button[kind="primary"] p {{ color:#1a1a1a; }}
      div.stButton>button[kind="primary"]:hover, div[data-testid="stFormSubmitButton"] button[kind="primary"]:hover {{ background:#e5b22b; border-color:#e5b22b; }}
      @media (max-width:850px) {{ .auth-banner {{ display:none; }} }}
    </style>
    """,
    unsafe_allow_html=True,
)


def extract_number(pattern: str, text: str, default: Optional[int] = None) -> Optional[int]:
    match = re.search(pattern, text or "", re.IGNORECASE | re.MULTILINE)
    if not match:
        return default
    try:
        return int(match.group(1).replace(",", ""))
    except (ValueError, IndexError):
        return default


def extract_scan_id(text: str) -> Optional[str]:
    match = re.search(r"Scan ID:\s*([^\s]+)", text or "", re.IGNORECASE)
    return match.group(1).strip(" ,") if match else None


def extract_report_path(text: str) -> Optional[str]:
    # Accept quoted paths or an unquoted path ending in .html, including spaces.
    patterns = [
        r"Report generated:\s*['\"](.+?\.html)['\"]",
        r"Report generated:\s*(.+?\.html)(?:\s*$)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text or "", re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


def resolve_report_path(output: str, scanner_dir: Path) -> Optional[Path]:
    raw_path = extract_report_path(output)
    if not raw_path:
        return None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = scanner_dir / candidate
    try:
        candidate = candidate.resolve()
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def metric_card(label: str, value: str, foot: str = "", tone: str = "") -> None:
    value_color = {"bad": C["bad"], "warn": C["warn"], "good": C["good"]}.get(tone, C["text"])
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{html.escape(label)}</div>'
        f'<div class="metric-value" style="color:{value_color}">{html.escape(value)}</div>'
        f'<div class="metric-foot">{html.escape(foot)}</div></div>',
        unsafe_allow_html=True,
    )


def get_auth_setting(name: str) -> str:
    """Read an authentication setting from the environment or Streamlit secrets."""
    value = os.getenv(name, "")
    if value:
        return value
    try:
        secret_value = st.secrets.get(name, "")
        return str(secret_value) if secret_value else ""
    except Exception:
        # A secrets.toml file is optional when environment variables are used.
        return ""


# Local account store for the Create account / Sign in screen.
# Passwords are salted and hashed; plain-text passwords are never stored.
AUTH_DB = Path(__file__).resolve().parent / "depguard_users.db"


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000).hex()
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False
def init_auth_db() -> None:
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salt_hex TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def create_account(full_name: str, email: str, password: str) -> tuple[bool, str]:
    init_auth_db()
    salt_hex, digest_hex = hash_password(password)
    try:
        with sqlite3.connect(AUTH_DB) as conn:
            conn.execute(
                "INSERT INTO users (full_name, email, salt_hex, password_hash) VALUES (?, ?, ?, ?)",
                (full_name.strip(), email.strip().lower(), salt_hex, digest_hex),
            )
            conn.commit()
        return True, "Account created. You can now sign in."
    except sqlite3.IntegrityError:
        return False, "An account with this email already exists. Please sign in instead."


def authenticate_account(email: str, password: str) -> Optional[str]:
    init_auth_db()
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute(
            "SELECT full_name, salt_hex, password_hash FROM users WHERE email = ? COLLATE NOCASE",
            (email.strip().lower(),),
        ).fetchone()
    if row and verify_password(password, row[1], row[2]):
        return str(row[0])
    return None


# Existing environment-configured admin login remains supported alongside local accounts.
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "Sign in"

configured_username = get_auth_setting("DEPGUARD_USERNAME")
configured_password = get_auth_setting("DEPGUARD_PASSWORD")

if not st.session_state.authenticated:
    left, right = st.columns([1.05, 0.95], gap="large")
    with left:
        st.markdown(
            '<div class="login-brand"><div class="login-icon">🛡️</div><div>'
            '<div class="eyebrow">DEPENDENCY SECURITY PLATFORM</div>'
            '<div class="login-title">DepGuard AI</div>'
            '<div class="login-subtitle">Secure your project, one dependency at a time.</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )
        mode = st.radio(
            "Account access",
            ["Sign in", "Create account"],
            horizontal=True,
            label_visibility="collapsed",
            key="auth_mode_selector",
        )
        st.session_state.auth_mode = mode

        if mode == "Create account":
            st.markdown("### Create an account")
            st.caption("Create a local account to access your dependency security dashboard.")
            with st.form("create_account_form", clear_on_submit=False):
                full_name = st.text_input("Full name", placeholder="Your name")
                email = st.text_input("Email", placeholder="you@example.com")
                new_password = st.text_input("Password", type="password", placeholder="At least 8 characters")
                confirm_password = st.text_input("Confirm password", type="password", placeholder="Re-enter your password")
                create_submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)
            if create_submitted:
                if not full_name.strip():
                    st.error("Enter your full name.")
                elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
                    st.error("Enter a valid email address.")
                elif len(new_password) < 8:
                    st.error("Use a password with at least 8 characters.")
                elif new_password != confirm_password:
                    st.error("The passwords do not match.")
                else:
                    ok, message = create_account(full_name, email, new_password)
                    if ok:
                        st.success(message + " Select **Sign in** above to continue.")
                    else:
                        st.error(message)
        else:
            st.markdown("### Welcome back")
            st.caption("Sign in to continue to your security dashboard.")
            with st.form("login_form", clear_on_submit=False):
                email_or_username = st.text_input("Email or admin username", placeholder="you@example.com")
                password = st.text_input("Password", type="password", placeholder="Your password")
                login_submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if login_submitted:
                user_name = authenticate_account(email_or_username, password) if "@" in email_or_username else None
                admin_ok = bool(
                    configured_username and configured_password
                    and hmac.compare_digest(email_or_username, configured_username)
                    and hmac.compare_digest(password, configured_password)
                )
                if user_name:
                    st.session_state.authenticated = True
                    st.session_state.current_user = user_name
                    st.rerun()
                elif admin_ok:
                    st.session_state.authenticated = True
                    st.session_state.current_user = configured_username
                    st.rerun()
                else:
                    st.error("Incorrect email/username or password. Please try again.")

        st.caption("Local accounts are stored in `depguard_users.db`. Passwords are stored as salted PBKDF2 hashes, not plain text.")
        if not configured_username or not configured_password:
            st.caption("Optional admin login: set `DEPGUARD_USERNAME` and `DEPGUARD_PASSWORD` environment variables.")
    with right:
        st.markdown(
            """
            <div class="auth-banner">
              <span class="auth-chip">🛡️ DEPENDENCY PROTECTION</span>
              <h2>Know what your project depends on.</h2>
              <p>Scan your project, review vulnerability evidence, and keep an eye on AI-assisted triage from one workspace.</p>
              <div class="auth-stat"><div class="auth-stat-label">DEPENDENCY ANALYSIS</div><div class="auth-stat-value">Scan with confidence</div><p>Check known vulnerability sources and inspect the generated report.</p></div>
              <div class="auth-stat"><div class="auth-stat-label">SECURITY WORKFLOW</div><div class="auth-stat-value">Find · Verify · Review</div><p>Keep scanner facts separate from AI-assisted interpretation.</p></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.stop()


# Sidebar settings and app context
with st.sidebar:
    st.markdown("## 🛡️ DepGuard AI")
    st.caption("Dependency vulnerability assessment")
    if st.session_state.current_user:
        st.caption(f"Signed in as {st.session_state.current_user}")
    st.divider()
    st.markdown("**Appearance**")
    selected_theme = st.radio(
        "Theme", ["Dark", "Light"], index=0 if st.session_state.theme == "Dark" else 1,
        horizontal=True, label_visibility="collapsed", key="theme_selector"
    )
    if selected_theme != st.session_state.theme:
        st.session_state.theme = selected_theme
        st.rerun()
    st.divider()
    st.markdown("**Scanner**")
    st.caption("The existing `app.py scan <project-path>` command is used. The scanner logic is not replaced by this UI.")
    st.caption("Keep this file in the same folder as `app.py`.")
    st.divider()
    if st.button("Log out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_user = ""
        st.rerun()

# Header
st.markdown(
    '<div class="hero"><div class="brandline"><div class="brandicon">🛡️</div>'
    '<div><div class="eyebrow">Dependency security platform</div>'
    '<div class="hero-title">DepGuard AI</div>'
    '<p class="hero-sub">Find known dependency vulnerabilities. Review evidence. Export a report.</p>'
    '</div></div><div class="pill">● Local project scan</div></div>',
    unsafe_allow_html=True,
)

# Scan input
st.markdown('<div class="panel-title">Start a security scan</div>', unsafe_allow_html=True)
st.markdown('<p class="panel-sub">Enter the absolute path to the project folder on the machine running this app.</p>', unsafe_allow_html=True)
with st.form("scan_form", clear_on_submit=False):
    project_path = st.text_input(
        "Project folder path",
        placeholder=r"C:\Projects\my-node-app  or  /home/user/my-node-app",
        help="Use a local path visible to the Python process running Streamlit.",
    )
    submitted = st.form_submit_button("▶  Start scan", type="primary", use_container_width=True)

if submitted:
    st.session_state.scan_success = False
    st.session_state.scan_output = ""
    st.session_state.scan_errors = ""
    st.session_state.scan_returncode = None
    st.session_state.report_path = None
    st.session_state.scan_id = None
    st.session_state.scanned_project = ""
    st.session_state.scan_duration_note = ""

    if not project_path.strip():
        st.error("Enter the project folder path to start a scan.")
    else:
        project = Path(project_path.strip().strip('"')).expanduser()
        scanner_dir = Path(__file__).resolve().parent
        app_path = scanner_dir / "app.py"
        if not project.is_dir():
            st.error("This folder does not exist or is not accessible to the Streamlit process. Check the path.")
        elif not app_path.is_file():
            st.error(f"Could not find the scanner CLI at `{app_path}`. Keep `ui.py` beside the existing `app.py`.")
        else:
            with st.spinner("Scanning dependencies and checking vulnerability sources… This may take several minutes."):
                try:
                    result = subprocess.run(
                        [sys.executable, str(app_path), "scan", str(project.resolve())],
                        capture_output=True,
                        text=True,
                        timeout=600,
                        cwd=str(scanner_dir),
                        check=False,
                    )
                    output = result.stdout or ""
                    errors = result.stderr or ""
                    st.session_state.scan_output = output
                    st.session_state.scan_errors = errors
                    st.session_state.scan_returncode = result.returncode
                    st.session_state.scan_id = extract_scan_id(output)
                    st.session_state.report_path = resolve_report_path(output, scanner_dir)
                    st.session_state.scan_success = result.returncode == 0
                    st.session_state.scanned_project = str(project.resolve())
                    if result.returncode != 0:
                        st.error("The scanner returned a non-zero exit code. Review the diagnostics below; partial output may still be useful.")
                except subprocess.TimeoutExpired as exc:
                    st.session_state.scan_output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                    st.session_state.scan_errors = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                    st.session_state.scan_success = False
                    st.session_state.scan_duration_note = "The scan exceeded the 10-minute timeout and was stopped."
                    st.error(st.session_state.scan_duration_note)
                except OSError as exc:
                    st.session_state.scan_success = False
                    st.session_state.scan_errors = str(exc)
                    st.error(f"Could not start the scanner process: {exc}")
                except Exception as exc:
                    st.session_state.scan_success = False
                    st.session_state.scan_errors = str(exc)
                    st.error(f"Unexpected scan error: {exc}")

# Results and tabs
has_output = bool(st.session_state.scan_output.strip())
if has_output:
    output = st.session_state.scan_output
    total_dependencies = extract_number(r"Extracted\s+([\d,]+)\s+dependencies", output)
    confirmed_vulnerabilities = extract_number(r"Confirmed Vulnerabilities:\s*([\d,]+)", output)
    ambiguous_findings = extract_number(r"Ambiguous:\s*([\d,]+)", output)
    scan_id = st.session_state.scan_id or "Not reported by scanner"

    st.markdown("### Scan overview")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        metric_card("Dependencies extracted", str(total_dependencies) if total_dependencies is not None else "—", "From scanner CLI output")
    with m2:
        metric_card("Confirmed vulnerabilities", str(confirmed_vulnerabilities) if confirmed_vulnerabilities is not None else "—", "Reported confirmed matches", "bad" if (confirmed_vulnerabilities or 0) > 0 else "good")
    with m3:
        metric_card("Needs review", str(ambiguous_findings) if ambiguous_findings is not None else "—", "Ambiguous findings", "warn" if (ambiguous_findings or 0) > 0 else "")
    with m4:
        metric_card("CLI exit code", str(st.session_state.scan_returncode) if st.session_state.scan_returncode is not None else "—", "0 means command succeeded", "good" if st.session_state.scan_returncode == 0 else "bad")

    if st.session_state.scan_success:
        if confirmed_vulnerabilities is not None and confirmed_vulnerabilities > 0:
            st.error(f"Vulnerabilities reported: {confirmed_vulnerabilities}. Review the findings and evidence before deciding on remediation.")
        elif ambiguous_findings is not None and ambiguous_findings > 0:
            st.warning("No confirmed count above zero was reported, but some findings need review. Do not interpret this as a clean bill of health.")
        elif confirmed_vulnerabilities == 0 and ambiguous_findings == 0:
            st.success("The scan command completed and reported zero confirmed and ambiguous findings. This only reflects the scanner's returned data and does not guarantee the project is vulnerability-free.")
        else:
            st.info("The scan command completed. Some summary counts were not found in the CLI output; use the report and raw output for details.")
    else:
        st.warning("The scan did not finish with exit code 0. Review diagnostics; do not treat missing results as a clean scan.")

    st.caption(f"**Scan ID:** {scan_id}  ·  **Project:** `{st.session_state.scanned_project or 'Unknown'}`")

    overview_tab, findings_tab, ai_tab, report_tab = st.tabs(["Overview", "Findings", "AI decisions", "Report"])
    with overview_tab:
        st.markdown("#### Scan execution")
        st.markdown(
            '<div class="panel"><div class="panel-title">What this dashboard can verify</div>'
            '<p class="panel-sub">The current frontend invokes the existing CLI and reads its output. It does not independently query the database or make new vulnerability decisions.</p>'
            '<span class="pill">CLI-driven results</span> &nbsp; '
            '<span class="pill">Report-backed details</span></div>',
            unsafe_allow_html=True,
        )
        if st.session_state.report_path:
            st.info("An HTML report was found. Open the Report tab to preview or download it.")
        else:
            st.info("No report path was detected in the scanner output. Check the raw output for the report-generation message.")

    with findings_tab:
        st.markdown("#### Vulnerability findings")
        report_path = st.session_state.report_path
        if report_path and report_path.is_file():
            st.caption("The generated HTML report is the available source for detailed findings. Preview it below.")
            try:
                report_html = report_path.read_text(encoding="utf-8", errors="replace")
                components.html(report_html, height=760, scrolling=True)
            except OSError as exc:
                st.warning(f"Could not read the report: {exc}")
        else:
            st.info("Detailed finding rows are not present in the captured CLI summary, and no HTML report was found. This UI intentionally does not invent a findings table. See Scan output below or ensure the scanner generates its report.")

    with ai_tab:
        st.markdown("#### AI-assisted triage")
        report_path = st.session_state.report_path
        report_text = ""
        if report_path and report_path.is_file():
            try:
                report_text = report_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        combined = output + "\n" + report_text
        ai_markers = re.findall(r".{0,100}(?:CONTINUE_TO_REPORT|VERIFY_WITH_ANOTHER_SOURCE|FLAG_FOR_REVIEW|ai_decision_outcome|ai_decider_used|Bedrock|Decider).{0,180}", combined, re.IGNORECASE)
        if ai_markers:
            st.caption("AI-related text found in scanner output/report. These are displayed as reported; the UI does not independently validate the decision.")
            for item in ai_markers[:30]:
                st.code(re.sub(r"<[^>]+>", " ", item).strip(), language="text")
            if len(ai_markers) > 30:
                st.caption(f"Showing 30 of {len(ai_markers)} matching lines/snippets.")
        else:
            st.info("No AI decision fields were detected in the CLI output or HTML report. The uploaded frontend does not expose a verified structured AI endpoint or database schema, so this panel will not fabricate Decider/Bedrock decisions.")
        st.markdown("**Expected decision labels (if emitted by the scanner):**")
        st.markdown("- `CONTINUE_TO_REPORT` — continue without extra verification.\n- `VERIFY_WITH_ANOTHER_SOURCE` — check a second source.\n- `FLAG_FOR_REVIEW` — mark for manual review.")

    with report_tab:
        st.markdown("#### Scan report")
        report_path = st.session_state.report_path
        if report_path and report_path.is_file():
            try:
                report_bytes = report_path.read_bytes()
                st.success(f"Report ready: `{report_path.name}`")
                st.download_button(
                    "⬇  Download HTML report", data=report_bytes,
                    file_name=report_path.name, mime="text/html",
                    type="primary", use_container_width=False,
                )
                with st.expander("Preview HTML report", expanded=True):
                    components.html(report_bytes.decode("utf-8", errors="replace"), height=700, scrolling=True)
                st.caption(f"Saved on the scanner machine at: {report_path}")
            except OSError as exc:
                st.warning(f"Could not read the report file: {exc}")
        else:
            st.warning("The scan output did not point to an existing HTML report. Check the raw output and scanner logs.")

    with st.expander("Raw scanner output and diagnostics"):
        st.markdown("**Standard output**")
        st.code(output or "(empty)", language="text")
        if st.session_state.scan_errors:
            st.markdown("**Standard error / diagnostics**")
            st.code(st.session_state.scan_errors, language="text")
else:
    st.markdown("### Your workflow")
    c1, c2, c3 = st.columns(3)
    steps = [
        ("01", "Choose a project", "Provide a folder path that the Streamlit server can access."),
        ("02", "Run the scanner", "DepGuard AI calls your existing Python CLI and waits for results."),
        ("03", "Review evidence", "Inspect the generated HTML report and download it for sharing."),
    ]
    for col, (number, title, desc) in zip((c1, c2, c3), steps):
        with col:
            st.markdown(
                f'<div class="step-card"><div class="step-number">STEP {number}</div>'
                f'<div class="step-title">{html.escape(title)}</div>'
                f'<div class="step-desc">{html.escape(desc)}</div></div>',
                unsafe_allow_html=True,
            )
    st.markdown("")
    st.info("Start by entering a project path above. This frontend keeps your current CLI scan behavior and adds a professional dashboard around its actual output.")

st.divider()
st.caption("DepGuard AI · Results are limited to the evidence returned by the configured scanner and data sources. A successful scan is not a guarantee of zero risk.")



