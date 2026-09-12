from __future__ import annotations

import json
from pathlib import Path

import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="PhantomRecon Dashboard",
    page_icon=":",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main .block-container {padding-top: 1rem;}
    .stMetric {background: #0e1117; border: 1px solid #262730; border-radius: 8px; padding: 12px;}
    .severity-CRITICAL {color: #ff4444;}
    .severity-HIGH {color: #ff8800;}
    .severity-MEDIUM {color: #ffcc00;}
    .severity-LOW {color: #44aaff;}
    .severity-INFO {color: #44ff44;}
</style>
""", unsafe_allow_html=True)


def load_results(results_dir: str) -> dict | None:
    path = Path(results_dir) / "findings.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


def main() -> None:
    st.title("PhantomRecon Dashboard")
    st.caption("Professional Bug Bounty Vulnerability Scanner")

    results_dir = st.sidebar.text_input("Results Directory", "scan_results")

    data = load_results(results_dir)

    if not data:
        st.info("No scan results found. Run a scan first with `phantomrecon scan --url <target>`")
        st.code("phantomrecon scan --url https://target.com", language="bash")
        return

    findings = data.get("findings", [])
    summary = data.get("summary", {})

    tab_overview, tab_findings, tab_scan = st.tabs(["Overview", "Findings", "Scan Details"])

    with tab_overview:
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Critical", summary.get("critical", 0), delta_color="inverse")
        col2.metric("High", summary.get("high", 0), delta_color="inverse")
        col3.metric("Medium", summary.get("medium", 0))
        col4.metric("Low", summary.get("low", 0))
        col5.metric("Total", data.get("total_findings", 0))

        st.divider()

        c1, c2 = st.columns(2)

        with c1:
            sev_counts = {
                s: sum(1 for f in findings if f["severity"] == s)
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                if sum(1 for f in findings if f["severity"] == s) > 0
            }
            if sev_counts:
                fig = px.pie(
                    names=list(sev_counts.keys()),
                    values=list(sev_counts.values()),
                    color=list(sev_counts.keys()),
                    color_discrete_map={
                        "CRITICAL": "#ff4444",
                        "HIGH": "#ff8800",
                        "MEDIUM": "#ffcc00",
                        "LOW": "#44aaff",
                        "INFO": "#44ff44",
                    },
                    title="Findings by Severity",
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)

        with c2:
            cat_counts = {}
            for f in findings:
                cat = f.get("category", "unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            if cat_counts:
                fig = px.bar(
                    x=list(cat_counts.keys()),
                    y=list(cat_counts.values()),
                    title="Findings by Category",
                    labels={"x": "Category", "y": "Count"},
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)

    with tab_findings:
        if not findings:
            st.info("No findings recorded.")
            return

        sev_filter = st.multiselect(
            "Filter by Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=["CRITICAL", "HIGH", "MEDIUM"],
        )
        filtered = [f for f in findings if f["severity"] in sev_filter]

        st.write(f"Showing {len(filtered)} of {len(findings)} findings")

        for f in filtered:
            severity = f["severity"]
            color_map = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44aaff", "INFO": "#44ff44"}
            color_map.get(severity, "#ffffff")

            with st.expander(f"[{severity}] {f['name']} — CVSS: {f.get('cvss_score', 0)}", expanded=(severity == "CRITICAL")):
                c1, c2 = st.columns(2)
                c1.markdown(f"**URL:** `{f.get('url', '')}`")
                c1.markdown(f"**Parameter:** `{f.get('parameter', '')}`")
                c1.markdown(f"**Method:** `{f.get('method', 'GET')}`")
                c2.markdown(f"**CWE:** {f.get('cwe', '')}")
                c2.markdown(f"**OWASP:** {f.get('owasp', '')}")
                c2.markdown(f"**Confidence:** {f.get('confidence', 0) * 100:.0f}%")

                if f.get("payload"):
                    st.markdown("**Payload:**")
                    st.code(f["payload"], language=None)

                if f.get("evidence"):
                    st.markdown("**Evidence:**")
                    st.code(f["evidence"][:500], language=None)

                st.markdown(f"**Description:** {f.get('description', '')}")
                st.markdown(f"**Remediation:** {f.get('remediation', '')}")

                if f.get("poc_curl"):
                    st.markdown("**PoC (curl):**")
                    st.code(f["poc_curl"], language="bash")

    with tab_scan:
        st.markdown(f"**Target:** {data.get('target', '')}")
        st.markdown(f"**URLs Scanned:** {data.get('urls_scanned', 0)}")
        st.markdown(f"**Modules Run:** {', '.join(data.get('modules_run', []))}")

        if data.get("errors"):
            st.warning("Errors during scan:")
            for err in data["errors"]:
                st.text(f"  - {err}")


if __name__ == "__main__":
    main()
