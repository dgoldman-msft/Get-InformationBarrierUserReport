"""
Information Barrier User Report Dashboard
==========================================
Streamlit web app that invokes Get-InformationBarrierUserReport and
visualises the results in a browser-based dashboard.

Usage
-----
    cd dashboard
    pip install -r requirements.txt
    streamlit run app.py
"""

import glob
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Information Barrier Report Dashboard",
    page_icon="🚧",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state defaults ────────────────────────────────────────────────────
_defaults: dict = {
    "output_lines": [],
    "error_lines":  [],
    "df":           None,
    "csv_path":     None,
    "ran":          False,
    "returncode":   None,
    "submitted_upns": [],
}
for _k, _v in _defaults.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Persistent pwsh sentinels ─────────────────────────────────────────────────
_SENTINEL     = "###GIBUR_DONE###"
_SENTINEL_ERR = "###GIBUR_ERR###"

# ── Settings persistence ──────────────────────────────────────────────────────
_SETTINGS_FILE = Path(__file__).resolve().parent / "dashboard_settings.json"

_default_psd1_path = str(
    Path(__file__).resolve().parent.parent
    / "1.0"
    / "Get-InformationBarrierUserReport.psd1"
)
_default_log_dir = os.path.join(
    os.environ.get("TEMP", "C:\\Temp"),
    "Get-InformationBarrierUserReport",
)

_SETTINGS_DEFAULTS: dict = {
    "module_path":        _default_psd1_path,
    "log_dir":            _default_log_dir,
    "auth_method":        "Interactive (browser / MFA)",
    "organization":       "",
    "cred_user":          "",
    "app_id":             "",
    "cert_thumb":         "",
    "opt_enumerate_users":  False,
    "opt_max_per_segment":  50,
    "opt_medium_details":   False,
    "opt_full_details":     False,
    "opt_stay_connected":   False,
}


def _load_settings() -> dict:
    settings = dict(_SETTINGS_DEFAULTS)
    if _SETTINGS_FILE.exists():
        try:
            saved = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
            for k, v in saved.items():
                if k in settings:
                    settings[k] = v
        except Exception:
            pass
    return settings


def _save_settings(s: dict) -> None:
    safe = {k: v for k, v in s.items() if k not in ("cred_pass",)}
    try:
        _SETTINGS_FILE.write_text(json.dumps(safe, indent=2), encoding="utf-8")
    except Exception:
        pass


if "_settings" not in st.session_state:
    st.session_state["_settings"] = _load_settings()

_s = st.session_state["_settings"]

for _k, _v in {"ps_proc": None, "ps_session_active": False}.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Status colours ────────────────────────────────────────────────────────────
STATUS_COLORS: dict[str, str] = {
    "Active":           "#2ecc71",
    "NoPolicyAssigned": "#f39c12",
    "NoSegment":        "#95a5a6",
    "Error":            "#e74c3c",
    "Unknown":          "#bdc3c7",
}

# ── Sidebar: settings ─────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")

    _s["module_path"] = st.text_input("Module path (.psd1)", value=_s["module_path"])
    _s["log_dir"]     = st.text_input("Log directory", value=_s["log_dir"])

    auth_options = [
        "Interactive (browser / MFA)",
        "Device code",
        "Credential",
        "Service Principal (cert thumbprint)",
        "Managed Identity",
    ]
    _s["auth_method"] = st.selectbox("Auth method", auth_options,
                                      index=auth_options.index(_s["auth_method"])
                                      if _s["auth_method"] in auth_options else 0)

    _s["organization"] = st.text_input("Organization (tenant domain)", value=_s["organization"],
                                        placeholder="contoso.onmicrosoft.com")

    if _s["auth_method"] == "Credential":
        _s["cred_user"] = st.text_input("Username (UPN)", value=_s["cred_user"])
        cred_pass = st.text_input("Password", type="password")
    elif _s["auth_method"] == "Service Principal (cert thumbprint)":
        _s["app_id"]     = st.text_input("Application ID", value=_s["app_id"])
        _s["cert_thumb"] = st.text_input("Certificate Thumbprint", value=_s["cert_thumb"])

    st.divider()
    st.subheader("Options")
    _s["opt_enumerate_users"] = st.checkbox("Enumerate users in segments", value=_s["opt_enumerate_users"])
    if _s["opt_enumerate_users"]:
        _s["opt_max_per_segment"] = st.number_input("Max users per segment", min_value=0,
                                                      max_value=10000, value=_s["opt_max_per_segment"])
    _s["opt_medium_details"]  = st.checkbox("Medium details", value=_s["opt_medium_details"])
    _s["opt_full_details"]    = st.checkbox("Full details",   value=_s["opt_full_details"])
    _s["opt_stay_connected"]  = st.checkbox("Stay connected", value=_s["opt_stay_connected"])

    if st.button("💾 Save settings"):
        _save_settings(_s)
        st.success("Settings saved.")

# ── Main area ─────────────────────────────────────────────────────────────────
st.title("🚧 Information Barrier User Report")
st.caption("Powered by Get-InformationBarrierUserReport · Microsoft Purview")

tabs = st.tabs(["▶ Run Report", "📊 Results", "📋 Raw Log"])

# ── Tab 0: Run Report ─────────────────────────────────────────────────────────
with tabs[0]:
    col1, col2 = st.columns([2, 1])
    with col1:
        mode = st.radio("Input mode", ["UPN lookup", "Segment enumeration", "List all policies"],
                        horizontal=True)

        upns_raw = segment_name = ""
        if mode == "UPN lookup":
            upns_raw = st.text_area("User/guest UPNs (one per line or comma-separated)",
                                     height=120,
                                     placeholder="jdoe@contoso.com\nguest_fabrikam.com#EXT#@contoso.onmicrosoft.com")
        elif mode == "Segment enumeration":
            segment_name = st.text_input("Segment name", placeholder="Finance")

    with col2:
        st.markdown("**Quick help**")
        st.markdown("""
- **UPN lookup** — report IB status for specific users/guests
- **Segment enumeration** — enumerate all users in a segment
- **List all policies** — print the full IB policy matrix
        """)

    run_clicked = st.button("▶ Run", type="primary", use_container_width=True)

    if run_clicked:
        # Build the PowerShell command
        ps_lines = [
            f"Import-Module '{_s['module_path']}' -Force",
        ]

        base_params: list[str] = []

        # Auth
        if _s["auth_method"] == "Device code":
            base_params.append("-UseDeviceAuthentication")
        elif _s["auth_method"] == "Credential":
            ps_lines.append(
                f"$cred = New-Object System.Management.Automation.PSCredential('{_s['cred_user']}',"
                f" (ConvertTo-SecureString '{cred_pass}' -AsPlainText -Force))"
            )
            base_params.append("-Credential $cred")
        elif _s["auth_method"] == "Service Principal (cert thumbprint)":
            base_params += [
                f"-ApplicationId '{_s['app_id']}'",
                f"-CertificateThumbprint '{_s['cert_thumb']}'",
            ]
        elif _s["auth_method"] == "Managed Identity":
            base_params.append("-ManagedIdentity")

        if _s["organization"]:
            base_params.append(f"-Organization '{_s['organization']}'")

        base_params.append(f"-LoggingDirectory '{_s['log_dir']}'")

        if _s["opt_enumerate_users"]:
            base_params.append("-EnumerateUsers")
            base_params.append(f"-MaxUsersPerSegment {_s['opt_max_per_segment']}")
        if _s["opt_medium_details"]:
            base_params.append("-MediumDetails")
        if _s["opt_full_details"]:
            base_params.append("-FullDetails")
        if _s["opt_stay_connected"]:
            base_params.append("-StayConnected")

        # Mode-specific
        if mode == "List all policies":
            base_params.append("-ListAll")
        elif mode == "Segment enumeration" and segment_name.strip():
            base_params.append(f"-Segment '{segment_name.strip()}'")
        elif mode == "UPN lookup" and upns_raw.strip():
            upns = [u.strip() for u in re.split(r"[\n,]+", upns_raw) if u.strip()]
            upn_list = ", ".join(f"'{u}'" for u in upns)
            base_params.append(f"-UserPrincipalName {upn_list}")
            st.session_state["submitted_upns"] = upns

        call = "Get-InformationBarrierUserReport " + " ".join(base_params)
        ps_lines.append(call)
        ps_lines.append(f'Write-Host "{_SENTINEL}"')

        ps_script = "; ".join(ps_lines)

        with st.spinner("Running Get-InformationBarrierUserReport…"):
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=300
            )

        st.session_state["output_lines"] = result.stdout.splitlines()
        st.session_state["error_lines"]  = result.stderr.splitlines()
        st.session_state["returncode"]   = result.returncode
        st.session_state["ran"]          = True

        # Find the newest CSV in log dir
        csv_pattern = os.path.join(_s["log_dir"], "IBReport_*.csv")
        csv_files = sorted(glob.glob(csv_pattern))
        if csv_files:
            newest_csv = csv_files[-1]
            try:
                df = pd.read_csv(newest_csv)
                st.session_state["df"]       = df
                st.session_state["csv_path"] = newest_csv
            except Exception as e:
                st.warning(f"Could not load CSV: {e}")
                st.session_state["df"] = None
        else:
            st.session_state["df"] = None

        if result.returncode == 0:
            st.success("Run completed successfully.")
        else:
            st.error(f"Run finished with exit code {result.returncode}. Check the Raw Log tab.")

# ── Tab 1: Results ────────────────────────────────────────────────────────────
with tabs[1]:
    df: pd.DataFrame | None = st.session_state.get("df")

    if df is None or df.empty:
        st.info("No results yet. Run a report first.")
    else:
        csv_path = st.session_state.get("csv_path", "")
        st.caption(f"Source: `{csv_path}`  ·  {len(df)} record(s)")

        # ── KPI cards
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            active = (df["IBStatus"] == "Active").sum() if "IBStatus" in df.columns else 0
            st.metric("Active IB policies", active)
        with c2:
            no_policy = (df["IBStatus"] == "NoPolicyAssigned").sum() if "IBStatus" in df.columns else 0
            st.metric("Segment / no policy", no_policy)
        with c3:
            no_seg = (df["IBStatus"] == "NoSegment").sum() if "IBStatus" in df.columns else 0
            st.metric("No segment", no_seg)
        with c4:
            errors = (df["IBStatus"] == "Error").sum() if "IBStatus" in df.columns else 0
            st.metric("Errors", errors)

        st.divider()

        col_left, col_right = st.columns(2)

        # ── IB Status pie
        with col_left:
            if "IBStatus" in df.columns:
                status_counts = df["IBStatus"].value_counts().reset_index()
                status_counts.columns = ["IBStatus", "Count"]
                colors = [STATUS_COLORS.get(s, "#bdc3c7") for s in status_counts["IBStatus"]]
                fig = px.pie(status_counts, names="IBStatus", values="Count",
                             title="IB Status Distribution",
                             color="IBStatus",
                             color_discrete_map=STATUS_COLORS)
                st.plotly_chart(fig, use_container_width=True)

        # ── Account type bar
        with col_right:
            if "AccountType" in df.columns:
                type_counts = df["AccountType"].value_counts().reset_index()
                type_counts.columns = ["AccountType", "Count"]
                fig2 = px.bar(type_counts, x="AccountType", y="Count",
                              title="Account Types", color="AccountType")
                st.plotly_chart(fig2, use_container_width=True)

        st.divider()
        st.subheader("All Records")

        # Filters
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            if "IBStatus" in df.columns:
                status_opts = ["All"] + sorted(df["IBStatus"].dropna().unique().tolist())
                sel_status = st.selectbox("Filter by IBStatus", status_opts)
        with filter_col2:
            if "AccountType" in df.columns:
                type_opts = ["All"] + sorted(df["AccountType"].dropna().unique().tolist())
                sel_type = st.selectbox("Filter by AccountType", type_opts)

        display_df = df.copy()
        if "IBStatus" in df.columns and sel_status != "All":
            display_df = display_df[display_df["IBStatus"] == sel_status]
        if "AccountType" in df.columns and sel_type != "All":
            display_df = display_df[display_df["AccountType"] == sel_type]

        st.dataframe(display_df, use_container_width=True)

        # Download
        csv_bytes = display_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download filtered CSV", csv_bytes, "IBReport_filtered.csv", "text/csv")

# ── Tab 2: Raw Log ────────────────────────────────────────────────────────────
with tabs[2]:
    if not st.session_state.get("ran"):
        st.info("No run yet.")
    else:
        rc = st.session_state.get("returncode")
        st.caption(f"Exit code: {rc}")
        if st.session_state["output_lines"]:
            st.text_area("stdout", "\n".join(st.session_state["output_lines"]), height=400)
        if st.session_state["error_lines"]:
            st.text_area("stderr", "\n".join(st.session_state["error_lines"]), height=200)
