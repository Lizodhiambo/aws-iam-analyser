import json
import os
from datetime import datetime, timezone
from pathlib import Path

# ─── Load findings from Phase 2 output ───────────────────────────────────────

FINDINGS_FILE = "iam_findings.json"

def load_findings():
    if not Path(FINDINGS_FILE).exists():
        print(f"[!] {FINDINGS_FILE} not found — run phase2_scanner.py first.")
        return []
    with open(FINDINGS_FILE) as f:
        return json.load(f)


# ─── HTML report generator ────────────────────────────────────────────────────

def generate_report(findings):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    total = len(findings)
    risk_level = "LOW"
    risk_colour = "#00c896"
    if counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
        risk_colour = "#ff4d4d"
    elif counts["HIGH"] > 0:
        risk_level = "HIGH"
        risk_colour = "#ffaa00"
    elif counts["MEDIUM"] > 0:
        risk_level = "MEDIUM"
        risk_colour = "#00bcd4"

    # Build finding rows
    def severity_badge(s):
        colours = {
            "CRITICAL": "#ff4d4d",
            "HIGH":     "#ffaa00",
            "MEDIUM":   "#00bcd4",
        }
        c = colours.get(s, "#888")
        return f'<span class="badge" style="background:{c}">{s}</span>'

    rows = ""
    if findings:
        for f in findings:
            rows += f"""
            <tr>
                <td>{severity_badge(f['severity'])}</td>
                <td>{f['category']}</td>
                <td><code>{f['resource']}</code></td>
                <td>{f['issue']}</td>
                <td>{f['recommendation']}</td>
            </tr>"""
    else:
        rows = """
            <tr>
                <td colspan="5" class="clean">
                    ✓ No issues found — your IAM configuration is clean!
                </td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>AWS IAM Security Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=DM+Sans:wght@300;400;600&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:        #0a0e17;
    --surface:   #111827;
    --border:    #1e2d40;
    --accent:    #00c896;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --critical:  #ff4d4d;
    --high:      #ffaa00;
    --medium:    #00bcd4;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    font-weight: 300;
    min-height: 100vh;
    padding: 48px 24px;
  }}

  /* grid background */
  body::before {{
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    opacity: 0.25;
    pointer-events: none;
    z-index: 0;
  }}

  .wrap {{
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
  }}

  /* ── Header ── */
  header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 48px;
    gap: 24px;
    flex-wrap: wrap;
  }}

  .logo {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--accent);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }}

  h1 {{
    font-size: clamp(28px, 4vw, 44px);
    font-weight: 600;
    line-height: 1.1;
    letter-spacing: -1px;
  }}

  h1 span {{ color: var(--accent); }}

  .meta {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--muted);
    margin-top: 12px;
    line-height: 1.8;
  }}

  .risk-pill {{
    background: {risk_colour}18;
    border: 1px solid {risk_colour};
    color: {risk_colour};
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    padding: 8px 20px;
    border-radius: 100px;
    letter-spacing: 2px;
    align-self: center;
    white-space: nowrap;
  }}

  /* ── Score cards ── */
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 40px;
  }}

  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
    animation: fadeUp 0.5s ease both;
  }}

  .card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }}

  .card.critical::before {{ background: var(--critical); }}
  .card.high::before     {{ background: var(--high); }}
  .card.medium::before   {{ background: var(--medium); }}
  .card.total::before    {{ background: var(--accent); }}

  .card-num {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 48px;
    font-weight: 400;
    line-height: 1;
    margin-bottom: 8px;
  }}

  .card.critical .card-num {{ color: var(--critical); }}
  .card.high     .card-num {{ color: var(--high); }}
  .card.medium   .card-num {{ color: var(--medium); }}
  .card.total    .card-num {{ color: var(--accent); }}

  .card-label {{
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
  }}

  /* ── Table ── */
  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
    animation: fadeUp 0.6s ease both;
  }}

  .table-header {{
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }}

  .table-header h2 {{
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}

  .dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 2s ease infinite;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}

  thead th {{
    padding: 12px 16px;
    text-align: left;
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    background: #0d1520;
    border-bottom: 1px solid var(--border);
  }}

  tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }}

  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: #ffffff06; }}

  tbody td {{
    padding: 14px 16px;
    vertical-align: top;
    line-height: 1.5;
  }}

  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 100px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    letter-spacing: 1px;
    color: #fff;
    white-space: nowrap;
  }}

  code {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    background: #ffffff0d;
    padding: 2px 6px;
    border-radius: 4px;
    color: var(--accent);
  }}

  .clean {{
    text-align: center;
    padding: 48px !important;
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 16px;
  }}

  /* ── Footer ── */
  footer {{
    margin-top: 40px;
    text-align: center;
    font-size: 12px;
    color: var(--muted);
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
  }}

  /* ── Animations ── */
  @keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
  }}

  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50%       {{ opacity: 0.3; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div>
      <div class="logo">AWS Security · IAM Analyser</div>
      <h1>IAM Security<br/><span>Report</span></h1>
      <div class="meta">
        Generated: {now}<br/>
        Framework: CIS AWS Foundations Benchmark<br/>
        Tool: aws-iam-analyser / Phase 3
      </div>
    </div>
    <div class="risk-pill">OVERALL RISK: {risk_level}</div>
  </header>

  <div class="cards">
    <div class="card critical">
      <div class="card-num">{counts['CRITICAL']}</div>
      <div class="card-label">Critical</div>
    </div>
    <div class="card high">
      <div class="card-num">{counts['HIGH']}</div>
      <div class="card-label">High</div>
    </div>
    <div class="card medium">
      <div class="card-num">{counts['MEDIUM']}</div>
      <div class="card-label">Medium</div>
    </div>
    <div class="card total">
      <div class="card-num">{total}</div>
      <div class="card-label">Total findings</div>
    </div>
  </div>

  <div class="table-wrap">
    <div class="table-header">
      <div class="dot"></div>
      <h2>Findings</h2>
    </div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>Resource</th>
          <th>Issue</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

  <footer>
    aws-iam-analyser · phase 3 report · {now}
  </footer>

</div>
</body>
</html>"""

    output = "iam_report.html"
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  Report saved → {output}")
    print(f"  Open it with: start {output}\n")
    return output


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n  AWS IAM Analyser — Phase 3: Report Generator\n")
    findings = load_findings()
    generate_report(findings)


if __name__ == "__main__":
    main()
