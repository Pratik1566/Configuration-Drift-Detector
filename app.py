
"""Drift — configuration comparison (Streamlit).

Run: streamlit run app.py
Files: core.py · data.py · explain.py · ui.py · security_baseline.py

Flow:
- Upload a CURRENT configuration.
- Optionally upload a custom BASELINE.
- Without a custom baseline, use the built-in standard security baseline.
"""

import json
from datetime import datetime
from pathlib import Path
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

import streamlit as st

from core import (
    RISK_ORDER,
    STANDARD_SECURITY_BASELINE,
    TYPE_LABEL,
    ConfigError,
    analyze,
    build_run,
    f_actual,
    f_expected,
    label,
    report_csv,
    report_data,
    totals,
)

from data import get_mock_servers
from explain import explain

from ui import (
    BRAND,
    CSS,
    FOOTER,
    baseline_table,
    chip,
    empty,
    empty_clean,
    empty_state,
    esc,
    features,
    finding_chips,
    fmt_date,
    hero,
    raw_json,
    ready_line,
    result_head,
    rich,
    ring,
    risk_badge,
    status_badge,
    step_head,
    time_ago,
    trend,
    type_badge,
    verdict,
)


st.set_page_config(
    page_title="Drift · Configuration comparison",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)

ss = st.session_state

DEC_FILE = Path(__file__).with_name("decisions.json")

NAV = [
    ("compare", "Compare"),
    ("findings", "Findings"),
    ("remediation", "Remediation"),
    ("reports", "Reports"),
]

PAGES = dict(NAV)


# ================================================================
# General helpers
# ================================================================

def H(html: str):
    """Render an HTML snippet."""

    if not html.startswith(("<div", "<svg", "<section", "<table")):
        html = f"<div>{html}</div>"

    st.markdown(html, unsafe_allow_html=True)


def load_decisions() -> dict:
    try:
        return json.loads(DEC_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_decisions():
    try:
        DEC_FILE.write_text(
            json.dumps(ss.decisions, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ================================================================
# Session state
# ================================================================

if "ready" not in ss:
    ss.ready = True

    qp = st.query_params.get("page", "compare")

    ss.page = qp if qp in PAGES else "compare"
    ss.run = None
    ss.history = []
    ss.decisions = load_decisions()
    ss.review_id = None
    ss.error = ""


def go(page: str):
    ss.page = page
    st.query_params["page"] = page


def open_review(fid: str):
    ss.review_id = fid


def decide(fid: str, status: str):
    if status == "Pending":
        ss.decisions.pop(fid, None)
        msg = "Decision reopened"

    else:
        ss.decisions[fid] = {
            "status": status,
            "by": "You",
            "at": datetime.now().isoformat(timespec="seconds"),
            "note": ss.get(f"note_{fid}", ""),
        }

        msg = (
            f"Fix {status.lower()} recorded. "
            "No server was changed."
        )

    save_decisions()

    ss.flash = msg
    ss.review_id = fid

    st.rerun()


def dstatus(fid: str) -> str:
    return ss.decisions.get(fid, {}).get("status", "Pending")


# ================================================================
# Standard baseline helpers
# ================================================================

def get_standard_rule_count(run: dict) -> int:
    """Return the number of standard rules applicable to this run."""

    rules = run.get("rules", [])

    if rules:
        return len(rules)

    group = run.get("rule_group")

    if group and group in STANDARD_SECURITY_BASELINE:
        return len(STANDARD_SECURITY_BASELINE[group])

    return 0


def get_manual_checks(result: dict) -> list:
    return result.get("manual_checks", [])


def get_rule_summary(result: dict) -> dict:
    rules = result.get("rules", [])

    return {
        "total": result.get("total_rules", len(rules)),
        "evaluated": result.get("evaluated_rules", 0),
        "passed": result.get("passed_rules", 0),
        "failed": result.get(
            "failed_rules",
            len(result.get("findings", [])),
        ),
        "manual": len(get_manual_checks(result)),
    }


def get_review_label(result: dict) -> str:
    if result.get("mode") == "standard":
        return "Standard Security Review"

    return "Custom Baseline Comparison"


# ================================================================
# Comparison
# ================================================================

def run_comparison(
    cur_name,
    cur_bytes,
    base_name=None,
    base_bytes=None,
):
    try:
        run = build_run(
            cur_name,
            cur_bytes,
            base_name,
            base_bytes,
        )

    except ConfigError as e:
        ss.error = str(e)
        return

    ss.run = run
    ss.error = ""

    result = analyze(run)

    ss.history.append({
        "time": run["last_scan"],
        "name": run["name"],
        "against": run["base_label"],
        "drifts": len(result["findings"]),
        "high": sum(
            f["risk"] == "High"
            for f in result["findings"]
        ),
        "score": result["score"],
    })

    ss.flash = "Comparison complete"

    go("findings")


def do_compare():
    cur = ss.get("up_cur")
    base = ss.get("up_base")

    if not cur:
        ss.error = "Add a current configuration file first."
        return

    run_comparison(
        cur.name,
        cur.getvalue(),
        base.name if base else None,
        base.getvalue() if base else None,
    )


def do_sample():
    sample = json.dumps(
        get_mock_servers()[0]["current"],
        indent=2,
    ).encode()

    run_comparison(
        "sample-server.json",
        sample,
    )


# ================================================================
# Current analysis
# ================================================================

A = [analyze(ss.run)] if ss.run else []

T = totals(A)

PENDING = sum(
    1
    for f in T["all"]
    if dstatus(f["id"]) == "Pending"
)

BY_ID = {
    f["id"]: (f, s)
    for s in A
    for f in s["findings"]
}


if ss.get("flash"):
    st.toast(ss.pop("flash"))


# ================================================================
# UI helpers
# ================================================================

def table(prefix: str, widths: list, headers: list, rows: list):
    """Render a styled table."""

    with st.container(key=f"tbl_{prefix}"):

        with st.container(key=f"thead_{prefix}"):

            for c, h in zip(st.columns(widths), headers):
                c.markdown(
                    f'<div class="th">{h}</div>',
                    unsafe_allow_html=True,
                )

        for i, row in enumerate(rows):

            with st.container(key=f"trow_{prefix}_{i}"):

                for c, cell in zip(
                    st.columns(
                        widths,
                        vertical_alignment="center",
                    ),
                    row,
                ):
                    with c:

                        if callable(cell):
                            cell()
                        else:
                            H(cell)


def review_btn(fid: str, ctx: str):
    def _draw():
        st.button(
            "Review",
            key=f"rev_{ctx}_{fid}",
            on_click=open_review,
            args=(fid,),
        )

    return _draw


def need_run(title: str, msg: str) -> bool:

    if ss.run:
        return False

    H(empty_state(title, msg))

    st.write("")

    _, mid, _ = st.columns([2, 1.2, 2])

    mid.button(
        "Start a comparison",
        key=f"start_{ss.page}",
        type="primary",
        on_click=go,
        args=("compare",),
    )

    return True


# ================================================================
# Top navigation
# ================================================================

active = ss.page

dyn = (
    f".st-key-nav_{active} button"
    "{background:var(--alt)!important;"
    "color:var(--ink)!important;"
    "font-weight:650!important}"
)

if PENDING:
    dyn += (
        '.st-key-nav_remediation button::after'
        f'{{content:"{PENDING}";'
        'margin-left:6px;'
        'background:#0071E3;'
        'color:#fff;'
        'border-radius:999px;'
        'font-size:.7rem;'
        'font-weight:600;'
        'padding:0 7px}'
    )

st.markdown(
    f"<style>{dyn}</style>",
    unsafe_allow_html=True,
)

with st.container(key="topnav"):

    cols = st.columns(
        [1.5, 0.95, 0.95, 1.25, 0.95, 3],
        vertical_alignment="center",
    )

    cols[0].markdown(
        BRAND,
        unsafe_allow_html=True,
    )

    for col, (key, text) in zip(cols[1:5], NAV):

        col.button(
            text,
            key=f"nav_{key}",
            on_click=go,
            args=(key,),
            use_container_width=True,
        )

    if ss.run:

        cols[5].markdown(
            f'<div class="nav-right">'
            f'{esc(ss.run["name"])} · '
            f'{time_ago(ss.run["last_scan"])}'
            f'</div>',
            unsafe_allow_html=True,
        )


# ================================================================
# Compare page
# ================================================================

def page_compare():

    H(hero())

    left, right = st.columns(2, gap="large")

    with left:

        with st.container(key="card_cur"):

            H(
                step_head(
                    "1",
                    "Current configuration",
                    "Required",
                    "req",
                    "The file you want to check.",
                )
            )

            st.file_uploader(
                "Current configuration",
                key="up_cur",
                label_visibility="collapsed",
            )

    with right:

        with st.container(key="card_base"):

            H(
                step_head(
                    "2",
                    "Baseline",
                    "Optional",
                    "opt",
                    "Upload your own baseline or use the built-in standard security baseline.",
                )
            )

            st.file_uploader(
                "Baseline",
                key="up_base",
                label_visibility="collapsed",
            )

    cur = ss.get("up_cur")
    base = ss.get("up_base")

    if cur and base:

        H(
            ready_line(
                f"<b>{esc(cur.name)}</b> will be compared with "
                f"your baseline <b>{esc(base.name)}</b>",
                True,
            )
        )

    elif cur:

        H(
            ready_line(
                f"<b>{esc(cur.name)}</b> will be checked against "
                f"the <b>standard secure baseline</b>",
                True,
            )
        )

    else:

        H(
            ready_line(
                "Add a current configuration to begin",
                False,
            )
        )

    if ss.error:

        _, mid, _ = st.columns([1, 3, 1])

        mid.error(ss.error)

    _, b1, b2, _ = st.columns(
        [2, 1.3, 1.3, 2],
        vertical_alignment="center",
    )

    b1.button(
        "Compare",
        key="do_compare",
        type="primary",
        disabled=not cur,
        on_click=do_compare,
        use_container_width=True,
    )

    b2.button(
        "Try sample data",
        key="do_sample",
        type="tertiary",
        on_click=do_sample,
        use_container_width=True,
    )

    st.write("")

    with st.expander("What is the standard baseline?"):

        st.caption(
            "The built-in baseline contains 106 rules across "
            "Ubuntu 22.04, SSH and NGINX. "
            "Only the applicable group is selected for a given configuration. "
            "Missing supported settings are treated as potential security drift."
        )

        H(baseline_table())

    H(features())


# ================================================================
# Findings page
# ================================================================

def page_findings():

    if need_run(
        "No results yet",
        "Upload a configuration on the Compare page and your findings will appear here.",
    ):
        return

    s = A[0]

    h1, h2 = st.columns(
        [5, 1.2],
        vertical_alignment="bottom",
    )

    # Correct review title for both comparison modes.
    review_label = get_review_label(s)

    h1.markdown(
        result_head(
            s["name"],
            s["kind"],
            review_label,
            fmt_date(s["last_scan"]),
        ),
        unsafe_allow_html=True,
    )

    h2.button(
        "New comparison",
        key="new_cmp",
        on_click=go,
        args=("compare",),
        use_container_width=True,
    )

    ca, cb = st.columns(
        [1, 2.3],
        gap="large",
    )

    with ca:

        with st.container(key="card_ring"):

            H(
                '<div class="center">'
                '<div class="card-title">Security posture</div>'
                + ring(s["score"])
                + '<p class="formula">'
                '100 − 15 per High − 7 per Medium − 2 per Low'
                '</p></div>'
            )

    with cb:

        with st.container(key="card_verdict"):

            verdict_count = (
                get_standard_rule_count(ss.run)
                if s["mode"] == "standard"
                else len(s.get("baseline", {}))
            )

            H(
                verdict(
                    s["findings"],
                    verdict_count,
                )
            )

    st.write("")

    # ------------------------------------------------------------
    # Standard baseline information
    # ------------------------------------------------------------

    if s["mode"] == "standard":

        total_rules = get_standard_rule_count(ss.run)
        summary = get_rule_summary(s)

        extra = ""

        if s.get("not_covered"):

            extra += (
                f'<b>{len(s["not_covered"])}</b> setting'
                f'{"s" if len(s["not_covered"]) != 1 else ""} '
                'in your file are not covered by the selected '
                'standard baseline and were left out. '
            )

        extra += (
            "Upload your own baseline to compare settings "
            "outside the selected standard rule group."
        )

        H(
            f'<div class="note">'
            f'<b>Applicable standard rules: {total_rules}.</b> '
            f'{extra}'
            f'</div>'
        )

        if (
            summary["evaluated"]
            or summary["passed"]
            or summary["failed"]
        ):

            st.write("")

            m1, m2, m3, m4 = st.columns(4)

            m1.metric(
                "Total rules",
                summary["total"] or total_rules,
            )

            m2.metric(
                "Evaluated",
                summary["evaluated"],
            )

            m3.metric(
                "Passed",
                summary["passed"],
            )

            m4.metric(
                "Failed",
                summary["failed"],
            )

        if summary["manual"]:

            with st.expander(
                f'Manual checks ({summary["manual"]})'
            ):

                for check in get_manual_checks(s):

                    st.markdown(
                        f'**{esc(str(check.get("title", check.get("setting", "Manual check"))))}**'
                    )

                    st.caption(
                        check.get(
                            "description",
                            "This check requires manual verification.",
                        )
                    )

        if s.get("not_covered"):

            with st.expander("Settings that weren't checked"):

                st.write(
                    ", ".join(
                        f"`{k}`"
                        for k in s["not_covered"]
                    )
                )

        st.write("")

    # ------------------------------------------------------------
    # Custom baseline informational section
    # ------------------------------------------------------------

    if s["mode"] == "custom":

        current_only = [
            (k, value)
            for k, value in s["current"].items()
            if k not in s["baseline"]
        ]

        if current_only:

            H(
                '<div class="card-title">'
                'Configurations Not Available in Baseline'
                '</div>'
            )

            st.caption(
                "These settings are present in the current configuration "
                "but do not exist in the uploaded baseline. "
                "They are listed for information only."
            )

            info_rows = []

            for setting, value in current_only:

                info_rows.append([
                    f'{esc(label(setting))}'
                    f'<span class="key">{esc(setting)}</span>',

                    chip(value, "", True),

                    '<span class="muted">'
                    'Not available to compare with baseline.'
                    '</span>',
                ])

            table(
                "current_only",
                [2, 1.2, 2.5],
                [
                    "Setting",
                    "Current value",
                    "Comparison status",
                ],
                info_rows,
            )

            st.write("")

    # ------------------------------------------------------------
    # Findings and raw data tabs
    # ------------------------------------------------------------

    t_find, t_raw = st.tabs([
        "Findings",
        "Raw data",
    ])

    with t_find:

        e1, e2, e3, _ = st.columns(
            [1, 1, 1.6, 2],
            vertical_alignment="bottom",
        )

        xr = e1.selectbox(
            "Risk",
            ["All", "High", "Medium", "Low"],
            key="x_risk",
        )

        xt = e2.selectbox(
            "Change",
            ["All", "Modified", "Added", "Removed"],
            key="x_type",
        )

        xu = e3.checkbox(
            "Show unchanged settings",
            key="x_unch",
        )

        if s["mode"] == "custom":

            keys = list(
                dict.fromkeys(
                    list(s["baseline"])
                    + list(s["current"])
                )
            )

            fmap = {
                f["setting"]: f
                for f in s["findings"]
            }

        else:

            fmap = {
                f["setting"]: f
                for f in s["findings"]
            }

            keys = list(fmap)

            if xu:
                keys = list(
                    dict.fromkeys(
                        keys + list(s.get("current", {}))
                    )
                )

        def sort_key(k):

            if k in fmap:
                return RISK_ORDER.get(
                    fmap[k]["risk"],
                    99,
                )

            return 99

        ordered = sorted(
            keys,
            key=sort_key,
        )

        rows = []

        for k in ordered:

            f = fmap.get(k)

            if not f and not xu:
                continue

            if xr != "All" and (
                not f or f["risk"] != xr
            ):
                continue

            if xt != "All" and (
                not f or f["type"] != xt.lower()
            ):
                continue

            typ = f["type"] if f else "same"

            if f:
                baseline_value = f_expected(f)
                current_value = f_actual(f)
            else:
                baseline_value = s.get(
                    "baseline",
                    {},
                ).get(k)

                current_value = s.get(
                    "current",
                    {},
                ).get(k)

            rows.append([
                (
                    f'{esc(label(k))}'
                    f'<span class="key">{esc(k)}</span>'
                ),

                chip(
                    baseline_value,
                    "",
                    baseline_value is not None,
                ),

                chip(
                    current_value,
                    "t-" + typ if f else "",
                    current_value is not None,
                ),

                type_badge(typ),

                risk_badge(f["risk"])
                if f else '<span class="muted">—</span>',

                status_badge(dstatus(f["id"]))
                if f else "",

                review_btn(f["id"], "ex")
                if f else "",
            ])

        if rows:

            table(
                "explorer",
                [2.2, 1.6, 1.6, 1.1, 1, 1.1, 1],
                [
                    "Setting",
                    "Baseline / Expected",
                    "Current",
                    "Change",
                    "Risk",
                    "Decision",
                    "",
                ],
                rows,
            )

        elif not s["findings"] and xr == "All" and xt == "All":

            H(
                empty_clean(
                    "Everything matches the baseline."
                )
            )

        else:

            H(
                empty(
                    "No settings match these filters"
                )
            )

    with t_raw:

        r1, r2 = st.columns(2)

        base_title = (
            "baseline"
            if s["mode"] == "custom"
            else "standard baseline"
        )

        r1.markdown(
            f'<div class="code-title">'
            f'{base_title} '
            '<span class="muted">· approved</span>'
            '</div>'
            + raw_json(
                s.get("baseline", {}),
                s["findings"],
            ),
            unsafe_allow_html=True,
        )

        r2.markdown(
            f'<div class="code-title">'
            f'{esc(s["name"])} '
            '<span class="muted">· observed</span>'
            '</div>'
            + raw_json(
                s["current"],
                s["findings"],
            ),
            unsafe_allow_html=True,
        )

        H(
            '<p class="hint">'
            'Highlighted lines differ from the baseline. '
            'SSH files are shown as normalised settings.'
            '</p>'
        )


# ================================================================
# Remediation page
# ================================================================

def page_remediation():

    H(
        '<div class="res-head">'
        '<div class="eyebrow">Remediation</div>'
        '<h1 style="font-family:inherit">'
        'Review proposed fixes'
        '</h1>'
        '<p class="sub muted" style="margin-top:8px">'
        'Approving records your decision only. '
        'Nothing is changed on any server.'
        '</p></div>'
    )

    if need_run(
        "Nothing to review yet",
        "Once a comparison finds drift, proposed fixes will be listed here.",
    ):
        return

    n = {
        "Pending": 0,
        "Approved": 0,
        "Rejected": 0,
    }

    for f in T["all"]:
        n[dstatus(f["id"])] += 1

    H(
        '<div class="mini-row">'
        + "".join(
            f'<div class="mini"><b>{v}</b>'
            f'<span class="muted">{k}</span></div>'
            for k, v in n.items()
        )
        + "</div>"
    )

    if not T["all"]:

        H(
            empty_clean(
                "There are no findings to remediate."
            )
        )

        return

    flt = st.selectbox(
        "Status",
        ["All", "Pending", "Approved", "Rejected"],
        key="f_rem",
    )

    order = {
        "Pending": 0,
        "Approved": 1,
        "Rejected": 2,
    }

    rows = [
        f
        for f in T["all"]
        if flt == "All" or dstatus(f["id"]) == flt
    ]

    rows.sort(
        key=lambda f: (
            order[dstatus(f["id"])],
            RISK_ORDER.get(f["risk"], 99),
        )
    )

    if not rows:

        H(
            empty(
                "Nothing to show",
                "No findings match this status.",
            )
        )

        return

    out = []

    for f in rows:

        d = ss.decisions.get(
            f["id"],
            {},
        )

        out.append([
            (
                f'{esc(label(f["setting"]))}'
                f'<span class="key">'
                f'{esc(f_expected(f))} → '
                f'{esc(f_actual(f))}'
                f'</span>'
            ),

            risk_badge(f["risk"]),

            status_badge(dstatus(f["id"])),

            esc(d.get("by", "—")),

            fmt_date(d["at"])
            if d.get("at")
            else "—",

            (
                f'<span class="muted">'
                f'{esc(d.get("note") or "—")}'
                f'</span>'
            ),

            review_btn(f["id"], "rem"),
        ])

    table(
        "rem",
        [2.4, 1, 1.1, 0.9, 1.4, 2, 1],
        [
            "Setting",
            "Risk",
            "Status",
            "Decided by",
            "When",
            "Note",
            "",
        ],
        out,
    )


# ================================================================
# PDF generation
# ================================================================

def create_pdf_report() -> bytes:
    """
    Generate a downloadable A4 PDF report using ReportLab.

    Install the dependency with:
        pip install reportlab
    """

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import (
            getSampleStyleSheet,
            ParagraphStyle,
        )
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            KeepTogether,
        )

    except ImportError as exc:
        raise RuntimeError(
            "PDF generation requires ReportLab. "
            "Install it using: pip install reportlab"
        ) from exc

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Drift Configuration Security Report",
        author="Drift Configuration Drift Detector",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=21,
            leading=26,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#172033"),
            spaceAfter=7,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=14,
            textColor=colors.HexColor("#596579"),
            spaceAfter=15,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#172033"),
            spaceBefore=13,
            spaceAfter=7,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#475467"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="TableText",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.white,
        )
    )

    story = []

    generated = datetime.now().strftime(
        "%d %B %Y, %I:%M %p"
    )

    total_findings = T["total"]
    high_count = T["c"]["High"]
    medium_count = T["c"]["Medium"]
    low_count = T["c"]["Low"]

    story.append(
        Paragraph(
            "Configuration Drift Report",
            styles["ReportTitle"],
        )
    )

    story.append(
        Paragraph(
            "Drift · Configuration Security Review",
            styles["ReportSubtitle"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Generated:</b> {xml_escape(generated)}"
            f"&nbsp;&nbsp;&nbsp; "
            f"<b>Security posture:</b> {T['posture']}/100",
            styles["Normal"],
        )
    )

    story.append(Spacer(1, 8))

    # ------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------

    story.append(
        Paragraph(
            "Executive Summary",
            styles["SectionHeading"],
        )
    )

    summary_data = [
        [
            Paragraph("<b>Total findings</b>", styles["SmallText"]),
            Paragraph("<b>High risk</b>", styles["SmallText"]),
            Paragraph("<b>Medium risk</b>", styles["SmallText"]),
            Paragraph("<b>Low risk</b>", styles["SmallText"]),
            Paragraph("<b>Posture</b>", styles["SmallText"]),
        ],
        [
            str(total_findings),
            str(high_count),
            str(medium_count),
            str(low_count),
            f"{T['posture']}/100",
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            34 * mm,
            30 * mm,
            32 * mm,
            28 * mm,
            28 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EAF0F7")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#172033")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D7DEE8")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    story.append(summary_table)
    story.append(Spacer(1, 8))

    # ------------------------------------------------------------
    # Each comparison
    # ------------------------------------------------------------

    for result in A:

        review_label = get_review_label(result)

        story.append(
            Paragraph(
                "Review Details",
                styles["SectionHeading"],
            )
        )

        metadata = [
            [
                Paragraph("<b>Review type</b>", styles["SmallText"]),
                Paragraph(
                    xml_escape(review_label),
                    styles["SmallText"],
                ),
            ],
            [
                Paragraph("<b>Configuration</b>", styles["SmallText"]),
                Paragraph(
                    xml_escape(str(result.get("name", "—"))),
                    styles["SmallText"],
                ),
            ],
            [
                Paragraph("<b>Compared against</b>", styles["SmallText"]),
                Paragraph(
                    xml_escape(str(result.get("base_label", "—"))),
                    styles["SmallText"],
                ),
            ],
            [
                Paragraph("<b>Scan date</b>", styles["SmallText"]),
                Paragraph(
                    xml_escape(str(result.get("last_scan", "—"))),
                    styles["SmallText"],
                ),
            ],
        ]

        metadata_table = Table(
            metadata,
            colWidths=[42 * mm, 130 * mm],
        )

        metadata_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F6FA")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D7DEE8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )

        story.append(metadata_table)

        if result.get("mode") == "standard":

            rule_count = get_standard_rule_count(ss.run)
            rule_summary = get_rule_summary(result)

            story.append(
                Paragraph(
                    "Standard Baseline Coverage",
                    styles["SectionHeading"],
                )
            )

            coverage_text = (
                f"Applicable standard rules: <b>{rule_count}</b><br/>"
                f"Evaluated: <b>{rule_summary['evaluated']}</b><br/>"
                f"Passed: <b>{rule_summary['passed']}</b><br/>"
                f"Failed: <b>{rule_summary['failed']}</b><br/>"
                f"Manual checks: <b>{rule_summary['manual']}</b>"
            )

            story.append(
                Paragraph(
                    coverage_text,
                    styles["SmallText"],
                )
            )

        # --------------------------------------------------------
        # Findings table
        # --------------------------------------------------------

        story.append(
            Paragraph(
                "Findings",
                styles["SectionHeading"],
            )
        )

        findings = result.get("findings", [])

        if findings:

            finding_rows = [[
                Paragraph("Setting", styles["TableHeader"]),
                Paragraph("Change", styles["TableHeader"]),
                Paragraph("Expected", styles["TableHeader"]),
                Paragraph("Actual", styles["TableHeader"]),
                Paragraph("Risk", styles["TableHeader"]),
                Paragraph("Decision", styles["TableHeader"]),
            ]]

            for finding in findings:

                setting = str(finding.get("setting", "—"))
                change = TYPE_LABEL.get(
                    finding.get("type", ""),
                    str(finding.get("type", "—")),
                )

                expected = str(f_expected(finding))
                actual = str(f_actual(finding))
                risk = str(finding.get("risk", "—"))
                decision = dstatus(finding["id"])

                finding_rows.append([
                    Paragraph(
                        xml_escape(label(setting))
                        + "<br/><font size='6' color='#667085'>"
                        + xml_escape(setting)
                        + "</font>",
                        styles["TableText"],
                    ),
                    Paragraph(xml_escape(change), styles["TableText"]),
                    Paragraph(xml_escape(expected), styles["TableText"]),
                    Paragraph(xml_escape(actual), styles["TableText"]),
                    Paragraph(xml_escape(risk), styles["TableText"]),
                    Paragraph(xml_escape(decision), styles["TableText"]),
                ])

            findings_table = Table(
                finding_rows,
                colWidths=[
                    43 * mm,
                    22 * mm,
                    34 * mm,
                    34 * mm,
                    17 * mm,
                    22 * mm,
                ],
                repeatRows=1,
                hAlign="LEFT",
            )

            findings_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#26364A")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D7DEE8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#F7F9FC"),
                    ]),
                ])
            )

            story.append(findings_table)

        else:

            story.append(
                Paragraph(
                    "No drift findings were detected in this comparison.",
                    styles["SmallText"],
                )
            )

        # --------------------------------------------------------
        # Manual checks
        # --------------------------------------------------------

        manual_checks = get_manual_checks(result)

        if manual_checks:

            story.append(
                Paragraph(
                    "Manual Checks",
                    styles["SectionHeading"],
                )
            )

            manual_rows = [[
                Paragraph("Check", styles["TableHeader"]),
                Paragraph("Description", styles["TableHeader"]),
            ]]

            for check in manual_checks:

                title = str(
                    check.get(
                        "title",
                        check.get("setting", "Manual check"),
                    )
                )

                description = str(
                    check.get(
                        "description",
                        "This check requires manual verification.",
                    )
                )

                manual_rows.append([
                    Paragraph(
                        xml_escape(title),
                        styles["TableText"],
                    ),
                    Paragraph(
                        xml_escape(description),
                        styles["TableText"],
                    ),
                ])

            manual_table = Table(
                manual_rows,
                colWidths=[55 * mm, 117 * mm],
                repeatRows=1,
            )

            manual_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#52647A")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D7DEE8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#F7F9FC"),
                    ]),
                ])
            )

            story.append(manual_table)

        not_covered = result.get("not_covered", [])

        if not_covered:

            story.append(
                Paragraph(
                    "Settings Outside the Selected Baseline",
                    styles["SectionHeading"],
                )
            )

            story.append(
                Paragraph(
                    xml_escape(", ".join(map(str, not_covered))),
                    styles["SmallText"],
                )
            )

    # ------------------------------------------------------------
    # Footer note and page numbering
    # ------------------------------------------------------------

    story.append(Spacer(1, 14))

    story.append(
        Paragraph(
            "<b>Important:</b> Detection and risk scoring are rule-based. "
            "AI is used only to explain findings. "
            "Manual checks require human verification. "
            "Approving a proposed fix records a decision only; "
            "this tool does not make changes to servers.",
            styles["SmallText"],
        )
    )

    def add_page_number(canvas, document):
        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#667085"))

        canvas.drawString(
            16 * mm,
            10 * mm,
            "Drift · Configuration Security Report",
        )

        canvas.drawRightString(
            A4[0] - 16 * mm,
            10 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    return buffer.getvalue()


# ================================================================
# Reports page
# ================================================================

def page_reports():

    H(
        '<div class="res-head">'
        '<div class="eyebrow">Reports</div>'
        '<h1 style="font-family:inherit">'
        'Export and history'
        '</h1>'
        '<p class="sub muted" style="margin-top:8px">'
        'Download the current findings and review earlier comparisons from this session.'
        '</p></div>'
    )

    if need_run(
        "No reports yet",
        "Run a comparison first, then export it here as JSON, CSV or PDF.",
    ):
        return

    with st.container(key="card_download"):

        H(
            '<div class="card-title" style="margin:0">'
            'Download report'
            '</div>'
        )

        st.caption(
            "Includes findings, risk levels, review decisions, "
            "standard baseline coverage and manual checks."
        )

        d1, d2, d3, _ = st.columns([
            1,
            1,
            1.6,
            3,
        ])

        d1.download_button(
            "JSON",
            json.dumps(
                report_data(A, ss.decisions),
                indent=2,
                default=str,
            ),
            "drift_report.json",
            "application/json",
            icon=":material/download:",
            key="dl_json",
        )

        d2.download_button(
            "CSV",
            report_csv(A, ss.decisions),
            "drift_report.csv",
            "text/csv",
            icon=":material/download:",
            key="dl_csv",
        )

        try:
            pdf_bytes = create_pdf_report()

            d3.download_button(
                "Download PDF",
                data=pdf_bytes,
                file_name="drift_security_report.pdf",
                mime="application/pdf",
                icon=":material/download:",
                key="dl_pdf",
                type="primary",
            )

        except RuntimeError as e:
            d3.error(str(e))

    st.write("")

    body = "".join(
        (
            f'<tr><td>{fmt_date(p["time"])}</td>'
            f'<td><span class="mono">{esc(p["name"])}</span></td>'
            f'<td>{esc(p["against"])}</td>'
            f'<td class="num"><b>{p["drifts"]}</b></td>'
            f'<td class="num">{p["high"]}</td>'
            f'<td class="num">{p["score"]}</td></tr>'
        )
        for p in reversed(ss.history)
    )

    H(
        '<div class="card-title">Comparisons this session</div>'
        '<div class="table-wrap"><table>'
        '<thead><tr>'
        '<th>Time</th>'
        '<th>File</th>'
        '<th>Compared with</th>'
        '<th class="num">Drifts</th>'
        '<th class="num">High</th>'
        '<th class="num">Score</th>'
        '</tr></thead>'
        f'<tbody>{body}</tbody></table></div>'
    )

    if len(ss.history) > 1:

        st.write("")

        with st.container(key="card_trend"):

            H(
                '<div class="card-title">'
                'Drift trend '
                '<small>Total drifts per comparison</small>'
                '</div>'
                + trend(ss.history)
            )


# ================================================================
# Review dialog
# ================================================================

def cached_explanation(f: dict) -> dict:
    return explain(f)


@st.dialog(
    "Finding details",
    width="large",
)
def review_dialog(fid: str):

    hit = BY_ID.get(fid)

    if not hit:

        st.write(
            "This finding is no longer available."
        )

        return

    f, s = hit

    with st.spinner("Loading explanation…"):

        exp = cached_explanation({
            k: f[k]
            for k in (
                "setting",
                "type",
                "expected",
                "actual",
                "risk",
            )
        })

    d = ss.decisions.get(fid)

    e_chip, a_chip = finding_chips(f)

    after = (
        '<span class="chip none">remove setting</span>'
        if f["type"] == "added"
        else e_chip
    )

    H(
        f'<div class="drawer-head">'
        f'<div class="eyebrow">{esc(s["name"])}</div>'
        f'<h2>{esc(label(f["setting"]))}</h2>'
        f'<code>{esc(f["setting"])}</code>'
        '</div>'

        f'<div class="badges">'
        f'{risk_badge(f["risk"])}'
        f'{type_badge(f["type"])}'
        f'{status_badge(dstatus(fid))}'
        '</div>'

        '<div class="sec" style="margin-top:0">'
        'Evidence<span class="tag tag-rule">Rule-based</span>'
        '</div>'

        f'<div class="evidence">'
        f'<div class="box"><div class="lbl">Expected (baseline)</div>{e_chip}</div>'
        '<div class="arr">→</div>'
        f'<div class="box"><div class="lbl">Actual (observed)</div>{a_chip}</div>'
        '</div>'

        '<div class="sec">Before / after fix</div>'

        f'<div class="evidence">'
        f'<div class="box"><div class="lbl">Now</div>{a_chip}</div>'
        '<div class="arr">→</div>'
        f'<div class="box"><div class="lbl">After fix</div>{after}</div>'
        '</div>'

        '<p class="hint">'
        'Proposed state only. Nothing is changed on the server.'
        '</p>'

        f'<div class="sec">'
        f'Explanation<span class="tag tag-ai">{esc(exp["source"])}</span>'
        '</div>'

        f'<div class="exp-block">'
        f'<h4>Why it matters</h4>'
        f'<p>{rich(exp["why_it_matters"])}</p>'
        '</div>'

        f'<div class="exp-block">'
        f'<h4>Impact</h4>'
        f'<p>{rich(exp["impact"])}</p>'
        '</div>'

        f'<div class="exp-block">'
        f'<h4>Suggested fix</h4>'
        f'<div class="fixbox">{rich(exp["suggested_fix"])}</div>'
        '</div>'
    )

    st.divider()

    if not d:

        H(
            '<div class="sec" style="margin-top:0">'
            'Your decision'
            '</div>'
        )

        st.text_area(
            "Note",
            key=f"note_{fid}",
            placeholder="Optional note (why you approve or reject)",
            label_visibility="collapsed",
        )

        b1, b2 = st.columns(2)

        if b1.button(
            "Approve fix",
            type="primary",
            key=f"ap_{fid}",
        ):
            decide(fid, "Approved")

        if b2.button(
            "Reject",
            key=f"rj_{fid}",
        ):
            decide(fid, "Rejected")

        H(
            '<p class="hint">'
            'Approving only records your decision. '
            'The tool never changes a server.'
            '</p>'
        )

    else:

        note = (
            f'<p style="margin-top:8px">“{esc(d["note"])}”</p>'
            if d.get("note")
            else ""
        )

        H(
            f'<div class="sec" style="margin-top:0">'
            f'Your decision</div>'
            f'<div class="decided">'
            f'{status_badge(d["status"])} '
            f'by <b>{esc(d["by"])}</b> · '
            f'{fmt_date(d["at"])}'
            f'{note}'
            f'</div>'
        )

        if st.button(
            "Reopen",
            key=f"ro_{fid}",
        ):
            decide(fid, "Pending")


# ================================================================
# Router
# ================================================================

{
    "compare": page_compare,
    "findings": page_findings,
    "remediation": page_remediation,
    "reports": page_reports,
}.get(
    ss.page,
    page_compare,
)()

H(FOOTER)

rid = ss.pop("review_id", None)

if rid:
    review_dialog(rid)
