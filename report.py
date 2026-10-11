"""PDF report generation for VULNEXIS scans (ReportLab)."""
import io
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    AVAILABLE = True
except ImportError:  # pragma: no cover
    AVAILABLE = False

SEV_COLOR = {"critical": "#D32F4A", "high": "#E8710A", "medium": "#B88A00", "low": "#1E88C8", "info": "#1F9E8F",
             "none": "#1F9E8F"}
INK = "#16203A"
MUTED = "#5B6784"
LINE = "#D5DBE8"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
MAX_TABLE_ROWS = 400
MAX_DETAIL_FINDINGS = 60


def esc(value):
    s = "" if value is None else str(value)
    return xml_escape(s.encode("latin-1", "replace").decode("latin-1"))


def build_pdf(meta, result):
    if not AVAILABLE:
        raise RuntimeError("The 'reportlab' package is not installed.")

    s = result["summary"]
    base = getSampleStyleSheet()
    st = {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24,
                                textColor=colors.HexColor(INK), alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9.5, leading=13, textColor=colors.HexColor(MUTED)),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16,
                             textColor=colors.HexColor(INK), spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9, leading=12.5, textColor=colors.HexColor(INK)),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8, leading=10.5, textColor=colors.HexColor(MUTED)),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8, leading=10, textColor=colors.HexColor(INK)),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10,
                                textColor=colors.HexColor(INK)),
        "head": ParagraphStyle("hd", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10,
                               textColor=colors.white),
        "stat": ParagraphStyle("st", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=20, leading=22,
                               textColor=colors.HexColor(INK)),
        "code": ParagraphStyle("cd", parent=base["Normal"], fontName="Courier", fontSize=7.5, leading=9.5,
                               textColor=colors.HexColor("#33405E"), leftIndent=8),
    }
    width = A4[0] - 32 * mm
    story = []

    # ---- Header
    story.append(Paragraph("VULNEXIS Quantum Cryptography Risk Report", st["title"]))
    when = meta.get("created_at", "")
    try:
        when = datetime.fromisoformat(when).strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        pass
    story.append(Paragraph(
        f"{esc(meta.get('label'))} (report for scan ID {meta.get('id')}). Run on {esc(when)}. "
        f"{s.get('files_scanned', 0)} files scanned in {result.get('duration_ms', 0)} ms.", st["sub"]))
    story.append(Spacer(1, 10))

    # ---- Score + stats
    lvl = s["risk_level"]
    lvl_col = colors.HexColor(SEV_COLOR.get(lvl, INK))
    score_cell = [Paragraph(f'<font color="{SEV_COLOR.get(lvl, INK)}">{s["risk_score"]}</font>'
                            f'<font size="10" color="{MUTED}"> / 100</font>', st["stat"]),
                  Paragraph(f"Risk level: <b>{esc(s['risk_level_label'])}</b>", st["body"])]
    stats = [
        ("Files scanned", s["files_scanned"]),
        ("Algorithms detected", s["algorithms_detected"]),
        ("Critical findings", s["critical_findings"]),
        ("Quantum-vulnerable assets", s["quantum_vulnerable_assets"]),
    ]
    cells = [score_cell] + [[Paragraph(str(v), st["stat"]), Paragraph(esc(k), st["small"])] for k, v in stats]
    t = Table([cells], colWidths=[width * 0.24] + [width * 0.19] * 4)
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor(LINE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.HexColor(LINE)),
        ("LINEABOVE", (0, 0), (0, 0), 3, lvl_col),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<b>Multi-Factor Prioritisation Methodology:</b> Each finding is evaluated using: "
        f"<b>Risk Score = (Cryptographic Vulnerability &times; 0.30) + (Data Sensitivity &times; 0.25) + "
        f"(Confidentiality Lifetime &times; 0.25) + (Asset Exposure &times; 0.20)</b>. "
        f"Threshold Bands: <b>Critical (80&ndash;100: Immediate attention)</b>, <b>High (60&ndash;79: This week)</b>, "
        f"<b>Medium (30&ndash;59: Planned migration)</b>, <b>Low (0&ndash;29: Monitor and maintain)</b>. "
        f"Overall scan prioritisation score: {s.get('risk_score', 0)}/100.", st["small"]))

    # ---- Severity breakdown
    story.append(Paragraph("Severity breakdown", st["h2"]))
    rows = [[Paragraph(h, st["head"]) for h in ("Severity", "Findings")]]
    for k in SEV_ORDER:
        rows.append([Paragraph(f'<font color="{SEV_COLOR[k]}"><b>{k.capitalize()}</b></font>', st["cell"]),
                     Paragraph(str(s["severity_counts"].get(k, 0)), st["cell"])])
    t = Table(rows, colWidths=[width * 0.3, width * 0.2], hAlign="LEFT")
    t.setStyle(_table_style())
    story.append(t)

    # ---- Monday Morning Action Plan ('What to Fix First')
    m_plan = result.get("monday_morning_plan")
    if m_plan and m_plan.get("buckets"):
        story.append(Paragraph("Monday Morning Action Plan (What to Fix First)", st["h2"]))
        story.append(Paragraph(
            "Developer-facing remediation priorities grouped into 4 actionable execution buckets. "
            "Prioritises long-lived confidential data subject to Harvest-Now-Decrypt-Later (HNDL) attacks.",
            st["small"]
        ))
        story.append(Spacer(1, 4))
        for b in m_plan["buckets"]:
            b_cnt = b["count"]
            b_col = SEV_COLOR.get(b["priority_level"], INK)
            b_block = [
                Paragraph(f'<font color="{b_col}"><b>[{b["title"].upper()}]</b></font> '
                          f'<b>{esc(b["timeframe"])}</b> &mdash; <i>{b_cnt} finding(s)</i>', st["cellb"]),
                Paragraph(f'<b>Target Owner:</b> {esc(b["owner_role"])} | <b>Rationale:</b> {esc(b["rationale"])}', st["small"]),
                Paragraph(f'<b>Prerequisites:</b> {esc(b["prerequisites"])}', st["small"]),
                Paragraph(f'<b>Validation Tests:</b> {esc(b["validation_tests"])}', st["small"]),
                Paragraph(f'<b>Expected Outcome:</b> {esc(b["expected_outcome"])}', st["small"]),
                Paragraph(f'<b>Concrete Next Action:</b> <font color="{b_col}"><b>{esc(b["concrete_next_action"])}</b></font>', st["cell"]),
            ]
            if b.get("items"):
                for it in b["items"][:3]:
                    b_block.append(Paragraph(
                        f"&bull; <b>{esc(it['priority_rank'])}</b> [{esc(it['severity'])} - Score {it['risk_score']}] "
                        f"<b>{esc(it['algorithm'])}</b> on <code>{esc(it['location'])}</code>: {esc(it['concrete_next_action'])}",
                        st["code"]
                    ))
                if len(b["items"]) > 3:
                    b_block.append(Paragraph(f"and {len(b['items']) - 3} more finding(s) in this bucket.", st["small"]))
            b_block.append(Spacer(1, 6))
            story.append(KeepTogether(b_block))

    if s["findings_total"] == 0:
        story.append(Spacer(1, 10))
        story.append(Paragraph("No cryptographic algorithms were detected in the scanned files.", st["body"]))

    # ---- Algorithm inventory
    if result["algorithms"]:
        story.append(Paragraph("Algorithm inventory", st["h2"]))
        rows = [[Paragraph(h, st["head"]) for h in ("Algorithm", "Category", "Severity", "Quantum status", "Uses", "Files")]]
        for a in result["algorithms"]:
            rows.append([Paragraph(esc(a["name"]), st["cellb"]), Paragraph(esc(a["category"]), st["cell"]),
                         Paragraph(f'<font color="{SEV_COLOR[a["severity"]]}"><b>{a["severity"].capitalize()}</b></font>', st["cell"]),
                         Paragraph(esc(a["quantum_label"]), st["cell"]),
                         Paragraph(str(a["occurrences"]), st["cell"]), Paragraph(str(a["files"]), st["cell"])])
        t = Table(rows, colWidths=[width * w for w in (0.30, 0.18, 0.12, 0.20, 0.10, 0.10)], repeatRows=1)
        t.setStyle(_table_style())
        story.append(t)

    # ---- Prioritized Remediation Queue
    queue = result.get("remediation_queue") or result.get("findings", [])
    if queue:
        story.append(Paragraph("Prioritized Remediation Queue", st["h2"]))
        story.append(Paragraph(
            "Ranked primarily by Risk Score descending, with ties broken by Confidentiality Lifetime descending, "
            "then Asset Exposure descending.", st["small"]
        ))
        rows = [[Paragraph(h, st["head"]) for h in ("Rank", "Score", "Severity", "Timeframe", "Algorithm", "Asset / Location", "Status")]]
        for q_item in queue[:MAX_TABLE_ROWS]:
            score_val = str(q_item.get("risk_score", "-"))
            s_level = q_item.get("severity_level") or q_item.get("risk_level") or q_item.get("severity", "medium").lower()
            rank_str = q_item.get("priority_rank") or f"#{q_item.get('id', '-')}"
            conf_str = "Provisional" if q_item.get("is_provisional") else "Confirmed"
            rows.append([
                Paragraph(f"<b>{esc(rank_str)}</b>", st["cellb"]),
                Paragraph(f"<b>{score_val}</b>", st["cellb"]),
                Paragraph(f'<font color="{SEV_COLOR.get(s_level, INK)}"><b>{esc(str(q_item.get("severity", "")).capitalize())}</b></font>', st["cell"]),
                Paragraph(esc(q_item.get("remediation_timeframe", q_item.get("timeframe", "-"))), st["cell"]),
                Paragraph(esc(q_item.get("algorithm", "-")), st["cellb"]),
                Paragraph(esc(q_item.get("location", q_item.get("file", "-"))), st["cell"]),
                Paragraph(f'<font color="{MUTED}"><i>{conf_str}</i></font>', st["small"]),
            ])
        t = Table(rows, colWidths=[width * w for w in (0.08, 0.08, 0.12, 0.20, 0.20, 0.22, 0.10)], repeatRows=1)
        t.setStyle(_table_style())
        story.append(t)
        if len(queue) > MAX_TABLE_ROWS:
            story.append(Paragraph(f"Showing the first {MAX_TABLE_ROWS} of {len(queue)} items in the queue.", st["small"]))

        story.append(Paragraph("Finding details", st["h2"]))
        for f in result["findings"][:MAX_DETAIL_FINDINGS]:
            conf_str = f"[{f['confidence_level'].capitalize()}] " if f.get("confidence_level") else ""
            key_str = f" ({f['key_size_label']})" if f.get("key_size_label") else ""
            mode_str = f" [Mode: {f['mode']}]" if f.get("mode") else ""
            q_class = (f.get("quantum_classification") or "not yet confidently classified").replace("-", " ").capitalize()
            breaks_str = "Yes" if f.get("breaks_security_assumptions") else "No"
            score_str = f" [Score: {f.get('risk_score', '-')}/100 - {f.get('priority', '')}]" if f.get("risk_score") is not None else ""

            block = [
                Paragraph(f'<font color="{SEV_COLOR[f["severity"]]}"><b>{f["severity"].upper()}</b></font> '
                          f'<b>{conf_str}{esc(f["algorithm"])}{key_str}{mode_str}</b> in {esc(f["file"])}'
                          f'<font color="{MUTED}"><b>{score_str}</b></font>', st["cellb"]),
            ]

            # Long-lived sensitive RSA/ECC alert callout
            if f.get("is_long_lived_sensitive_pki"):
                block.append(Paragraph(
                    f'<font color="#D32F4A"><b>[ALERT: LONG-LIVED SENSITIVE ASSET ON RSA/ECC]</b></font> '
                    f'<i>{esc(f.get("highlight_callout", ""))}</i>', st["cell"]
                ))

            if f.get("is_provisional"):
                block.append(Paragraph(
                    f'<font color="#E8710A"><b>[PROVISIONAL SCORE &ndash; DEFAULT ASSUMPTIONS]</b></font> '
                    f'<i>{esc(f.get("score_explanation", ""))}</i>', st["small"]
                ))

            # Contributing factors summary
            if f.get("contributing_factors"):
                f_summary = " | ".join(f"{fc['name'].split()[0]}: {fc['raw_score']}/100 ({fc['weighted_score']} pts)" for fc in f["contributing_factors"])
                block.append(Paragraph(f"<b>Contributing Factors:</b> {esc(f_summary)}", st["small"]))

            block.append(Paragraph(f"<b>Quantum Classification:</b> {esc(q_class)} | <b>Breaks Assumptions:</b> {breaks_str}", st["cell"]))

            # Quantum Threat / Why vulnerable
            if f.get("why_vulnerable"):
                block.append(Paragraph(f"<b>Quantum Threat (CRQC):</b> {esc(f['why_vulnerable'])}", st["cell"]))
            elif f.get("quantum_risk_assessment", {}).get("description"):
                block.append(Paragraph(f"<b>Quantum Threat (CRQC):</b> {esc(f['quantum_risk_assessment']['description'])}", st["cell"]))

            # Classical Concerns
            c_sec = f.get("current_security_concerns") or {}
            c_concerns = c_sec.get("concerns") or []
            if c_concerns:
                exp_label = "Actively Exploitable" if c_sec.get("exploitable_today") else "Classically Secure"
                ref_txt = f" (Ref: {c_sec['standards_reference']})" if c_sec.get("standards_reference") else ""
                block.append(Paragraph(f"<b>Classical Security [{exp_label}]:</b> {esc('; '.join(c_concerns))}{esc(ref_txt)}", st["cell"]))
            elif f.get("classical_security_assessment", {}).get("description"):
                block.append(Paragraph(f"<b>Classical Security:</b> {esc(f['classical_security_assessment']['description'])}", st["cell"]))

            # Harvest-Now-Decrypt-Later
            hndl = f.get("harvest_now_decrypt_later") or {}
            if hndl.get("applicable"):
                block.append(Paragraph(f"<b>Harvest-Now-Decrypt-Later (HNDL):</b> [Risk: {hndl.get('risk_level', '').upper()}] {esc(hndl.get('explanation', ''))}", st["cell"]))

            # PQC Migration Recommendation
            m_rec = f.get("migration_recommendation") or {}
            if m_rec and m_rec.get("proposed_alternative"):
                block.append(Paragraph(
                    f'<b>PQC Migration Alternative:</b> <font color="{SEV_COLOR.get(f["severity"], INK)}"><b>{esc(m_rec.get("proposed_alternative", ""))}</b></font> '
                    f'<i>[Role: {esc(m_rec.get("protocol_role", ""))} | Priority: {esc(m_rec.get("priority", ""))}]</i>',
                    st["cell"]
                ))
                if m_rec.get("reason"):
                    block.append(Paragraph(f'<b>Migration Rationale:</b> {esc(m_rec["reason"])}', st["cell"]))
                if m_rec.get("compatibility_considerations"):
                    block.append(Paragraph(f'<b>Compatibility Notes:</b> {esc(m_rec["compatibility_considerations"])}', st["small"]))
                if m_rec.get("implementation_steps"):
                    steps_txt = " &bull; ".join(esc(s) for s in m_rec["implementation_steps"][:4])
                    block.append(Paragraph(f'<b>Implementation Steps:</b> {steps_txt}', st["small"]))
                if m_rec.get("testing_requirements"):
                    test_txt = " &bull; ".join(esc(t) for t in m_rec["testing_requirements"][:3])
                    block.append(Paragraph(f'<b>Testing Requirements:</b> {test_txt}', st["small"]))
            else:
                remed = f.get("remediation_guidance") or {}
                repl_val = remed.get("recommended_replacement") or f.get("replacement") or ""
                strat_val = remed.get("transition_strategy") or f.get("recommendation") or ""
                block.append(Paragraph(f"<b>Recommended Action:</b> {esc(strat_val)} (Replace with: <b>{esc(repl_val)}</b>)", st["cell"]))

            # Evidence
            if f.get("evidence"):
                block.append(Paragraph(f"<b>Evidence:</b> {esc(f['evidence'])}", st["code"]))

            for o in f["occurrences"][:2]:
                where = f"line {o['line']}" if o["line"] else "binary file"
                block.append(Paragraph(esc(f"{where}: {o['snippet']}"), st["code"]))
            if f["count"] > 2:
                block.append(Paragraph(f"and {f['count'] - 2} more use(s) in this file", st["small"]))

            # Limitations
            if f.get("analysis_limitations"):
                block.append(Paragraph(f"<b>Limitations:</b> {esc('; '.join(f['analysis_limitations']))}", st["small"]))

            block.append(Spacer(1, 7))
            story.append(KeepTogether(block))
        if len(result["findings"]) > MAX_DETAIL_FINDINGS:
            story.append(Paragraph(f"Details shown for the {MAX_DETAIL_FINDINGS} highest-severity findings.", st["small"]))

    # ---- Migration plan
    phases = result["plan"]["phases"]
    story.append(Paragraph("Post-quantum migration plan", st["h2"]))
    if not phases:
        story.append(Paragraph("No migration steps are needed based on this scan.", st["body"]))
    else:
        for i, ph in enumerate(phases, 1):
            block = [Paragraph(f"<b>Phase {i}: {esc(ph['title'])}</b> ({esc(ph['priority'])})", st["cellb"]),
                     Paragraph(esc(ph["intro"]), st["small"]), Spacer(1, 3)]
            for a in ph["actions"]:
                extra = f" - {a['file_count']} file(s), {a['uses']} use(s)" if a["file_count"] else ""
                block.append(Paragraph(f"- <b>{esc(a['title'])}</b>{esc(extra)}. Replace with: <b>{esc(a['replace_with'])}</b>. "
                                       f"{esc(a['how'])}", st["cell"]))
                if a.get("compatibility_considerations"):
                    block.append(Paragraph(f"  <i>Compatibility:</i> {esc(a['compatibility_considerations'])}", st["small"]))
                if a.get("implementation_steps"):
                    block.append(Paragraph(f"  <i>Steps:</i> {' | '.join(esc(s) for s in a['implementation_steps'][:3])}", st["small"]))
                if a.get("testing_requirements"):
                    block.append(Paragraph(f"  <i>Testing:</i> {' | '.join(esc(t) for t in a['testing_requirements'][:2])}", st["small"]))
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))
        for ref in result["plan"]["references"]:
            story.append(Paragraph(esc(ref), st["small"]))

    # ---- Skipped
    if result["skipped"]["total"]:
        story.append(Paragraph("Files not inspected", st["h2"]))
        story.append(Paragraph(f"{result['skipped']['total']} file(s) were skipped.", st["body"]))
        rows = [[Paragraph(h, st["head"]) for h in ("File", "Reason")]]
        for it in result["skipped"]["items"][:60]:
            rows.append([Paragraph(esc(it["name"]), st["cell"]), Paragraph(esc(it["reason"]), st["cell"])])
        t = Table(rows, colWidths=[width * 0.7, width * 0.3], repeatRows=1)
        t.setStyle(_table_style())
        story.append(t)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "VULNEXIS reports algorithm usage found by pattern matching and by parsing certificates and keys. A match "
        "shows where an algorithm is named, not proof that it protects live data. Review each finding in context.",
        st["small"]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.drawString(16 * mm, 9 * mm, f"VULNEXIS scan report, scan {meta.get('id')}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                      bottomMargin=18 * mm, title=f"VULNEXIS report - {meta.get('label')}", author="VULNEXIS"
                      ).build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def _table_style():
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B3A63")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F5FA")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(LINE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ])
