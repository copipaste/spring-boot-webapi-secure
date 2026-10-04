#!/usr/bin/env python3
"""Quality Gate de seguridad.

Lee los reportes que producen los escaneres (Semgrep, CodeQL, SpotBugs + FindSecBugs,
Trivy sobre el SBOM y OWASP Dependency-Check), los clasifica por severidad y falla
(exit code 1) si:

  * algun hallazgo alcanza el umbral (por defecto HIGH, que incluye CRITICAL), o
  * un job requerido termino en failure / cancelled / skipped, o
  * un job termino bien pero no dejo su reporte (evita el "verde vacio").

En el pipeline (job "Quality Gate"):
    NEEDS_JSON='${{ toJSON(needs) }}' python3 .github/scripts/quality_gate.py --reports reports

En local, sobre tus propios reportes (sin resultados de jobs):
    python .github/scripts/quality_gate.py --reports target --no-needs --allow-missing

Solo usa la libreria estandar de Python.
"""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter, namedtuple
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

Finding = namedtuple("Finding", "severity title location")


# --------------------------------------------------------------------------- utilidades
def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def score_to_severity(score):
    """CVSS / security-severity -> CRITICAL, HIGH, MEDIUM, LOW."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def normalize_severity(value):
    value = str(value or "").strip().upper()
    if value == "MODERATE":
        value = "MEDIUM"
    return value if value in RANK else None


def find_report(root, filename):
    """Busca el archivo en cualquier subcarpeta (download-artifact crea una por artefacto)."""
    matches = sorted(Path(root).rglob(filename))
    return matches[0] if matches else None


# --------------------------------------------------------------------------- parsers
def parse_semgrep(path):
    out = []
    for r in load_json(path).get("results", []):
        extra = r.get("extra", {})
        sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
            str(extra.get("severity", "")).upper(), "LOW")
        loc = f'{r.get("path")}:{(r.get("start") or {}).get("line")}'
        out.append(Finding(sev, r.get("check_id", "?"), loc))
    return out


def parse_sarif(path):
    out = []
    for run in load_json(path).get("runs", []):
        tool = run.get("tool", {})
        driver_rules = list(tool.get("driver", {}).get("rules", []))
        rules = list(driver_rules)
        for ext in tool.get("extensions", []) or []:
            rules.extend(ext.get("rules", []) or [])
        by_id = {r.get("id"): r for r in rules}
        for res in run.get("results", []) or []:
            if res.get("suppressions"):
                continue
            rule = by_id.get(res.get("ruleId"))
            idx = res.get("ruleIndex")
            if rule is None and isinstance(idx, int) and 0 <= idx < len(driver_rules):
                rule = driver_rules[idx]
            rule = rule or {}
            sev = score_to_severity((rule.get("properties") or {}).get("security-severity"))
            if sev is None:  # alertas de calidad, sin security-severity
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
                sev = "MEDIUM" if level == "error" else "LOW"
            loc = ""
            locations = res.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation", {})
                loc = f'{(phys.get("artifactLocation") or {}).get("uri", "")}:{(phys.get("region") or {}).get("startLine", "")}'
            out.append(Finding(sev, res.get("ruleId", "?"), loc))
    return out


def parse_spotbugs(path):
    out = []
    root = ET.parse(path).getroot()
    for bug in root.iter("BugInstance"):
        prio = bug.get("priority", "3")
        try:
            rank = int(bug.get("rank") or 20)
        except ValueError:
            rank = 20
        # Umbrales a calibrar con el primer reporte real (ver INFORME-LAB3.md, seccion 6.2)
        if prio == "1" or rank <= 4:
            sev = "HIGH"
        elif prio == "2" or rank <= 9:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        cls = bug.find("Class")
        src = bug.find("SourceLine")
        loc = (cls.get("classname") if cls is not None else "") or ""
        if src is not None and src.get("start"):
            loc += f':{src.get("start")}'
        out.append(Finding(sev, bug.get("type", "?"), loc))
    return out


def parse_trivy(path):
    out = []
    for res in load_json(path).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            sev = normalize_severity(v.get("Severity")) or "LOW"
            fixed = v.get("FixedVersion")
            loc = f'{v.get("PkgName")}@{v.get("InstalledVersion")} ' + (f"(fix: {fixed})" if fixed else "(sin fix)")
            out.append(Finding(sev, v.get("VulnerabilityID", "?"), loc))
    return out


def parse_odc(path):
    out = []
    for dep in load_json(path).get("dependencies") or []:
        for v in dep.get("vulnerabilities") or []:  # las suprimidas van en "suppressedVulnerabilities"
            sev = normalize_severity(v.get("severity"))
            if sev is None:
                score = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv2") or {}).get("score")
                sev = score_to_severity(score) or "LOW"
            out.append(Finding(sev, v.get("name", "?"), dep.get("fileName", "")))
    return out


# id del job, titulo, archivo de reporte, parser, (aplica solo si ODC esperado)
TOOLS = [
    ("sast-semgrep", "Semgrep (SAST)", "semgrep-results.json", parse_semgrep, False),
    ("sast-codeql", "CodeQL (SAST)", "java.sarif", parse_sarif, False),
    ("static-analysis", "SpotBugs + FindSecBugs", "spotbugsXml.xml", parse_spotbugs, False),
    ("sca-sbom", "Trivy sobre SBOM (SCA)", "sca-report.json", parse_trivy, False),
    ("sca-dependency-check", "OWASP Dependency-Check (SCA)", "dependency-check-report.json", parse_odc, True),
]
PLAIN_JOBS = [
    ("build-and-test", "Build & Test (JUnit + JaCoCo)"),
    ("docker-smoke-test", "Docker: build + smoke test"),
]


# --------------------------------------------------------------------------- evaluacion
def evaluate(args, needs):
    threshold = RANK[args.fail_on]
    rows, details, failures = [], [], []

    def job_state(job):
        return None if needs is None else (needs.get(job) or {}).get("result", "missing")

    for job, title in PLAIN_JOBS:
        state = job_state(job)
        if state is None or state == "success":
            rows.append((title, None, "OK" if state else "n/a"))
        else:
            rows.append((title, None, f"FALLA (job: {state})"))
            failures.append(f"{title}: el job termino en '{state}'")

    for job, title, filename, parser, odc_only in TOOLS:
        if odc_only and not args.odc_expected:
            rows.append((title, None, "no aplica (solo nightly)"))
            continue
        state = job_state(job)
        problems = []
        if state is not None and state != "success":
            problems.append(f"job termino en '{state}'")
        report = find_report(args.reports, filename)
        counts, findings = Counter(), []
        if report is None:
            if state in (None, "success") and not args.allow_missing:
                problems.append(f"no se encontro el reporte '{filename}'")
            elif state in (None, "success"):
                rows.append((title, None, "sin reporte (omitido)"))
                continue
        else:
            try:
                findings = parser(report)
            except Exception as exc:  # reporte corrupto = no se puede confiar en el resultado
                problems.append(f"no se pudo leer '{report.name}': {exc}")
            counts = Counter(f.severity for f in findings)
        blocking = [f for f in findings if RANK[f.severity] >= threshold]
        if blocking:
            problems.append(f"{len(blocking)} hallazgo(s) >= {args.fail_on}")
        status = "OK" if not problems else "FALLA (" + "; ".join(problems) + ")"
        rows.append((title, counts, status))
        if problems:
            failures.append(f"{title}: " + "; ".join(problems))
        if blocking:
            blocking.sort(key=lambda f: -RANK[f.severity])
            details.append((title, blocking))
    return rows, details, failures


def render(args, rows, details, failures):
    ok = not failures
    lines = ["## Quality Gate", "",
             f"**Resultado: {'APROBADO' if ok else 'RECHAZADO'}** - umbral: {args.fail_on} "
             f"{'(y CRITICAL) ' if args.fail_on != 'CRITICAL' else ''}bloquea el pipeline", "",
             "| Control | CRITICAL | HIGH | MEDIUM | LOW | Estado |", "|---|--:|--:|--:|--:|---|"]
    for title, counts, status in rows:
        if counts is None:
            cells = ["-"] * 4
        else:
            cells = [str(counts.get(s, 0)) for s in SEVERITIES]
        lines.append(f"| {title} | " + " | ".join(cells) + f" | {status} |")
    if details:
        lines += ["", "### Hallazgos que bloquean"]
        for title, blocking in details:
            lines += ["", f"**{title}** - {len(blocking)} bloqueante(s)"]
            for f in blocking[: args.max_listed]:
                lines.append(f"- `{f.severity}` {f.title[:100]} - `{f.location[:160]}`")
            if len(blocking) > args.max_listed:
                lines.append(f"- ... y {len(blocking) - args.max_listed} mas (ver el reporte completo en los artefactos)")
    if failures:
        lines += ["", "### Motivos del rechazo"] + [f"- {m}" for m in failures]
    lines += ["", "_Los hallazgos MEDIUM/LOW se listan en los reportes pero no bloquean. "
              "Las excepciones aceptadas se documentan (supresiones, `# nosemgrep`), no se baja el umbral._"]
    return "\n".join(lines) + "\n"


def annotate(args, rows, details, failures, text):
    """En GitHub Actions publica el resultado como anotaciones (visibles en la pagina de la ejecucion y por API)."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    def esc(value, prop=False):
        value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return value.replace(":", "%3A").replace(",", "%2C") if prop else value

    print(f"::notice title={esc('Quality Gate - resumen', True)}::{esc(text)}")
    if not failures:
        return
    blocking_by_title = dict(details)
    for title, _counts, status in rows:
        if not status.startswith("FALLA"):
            continue
        top = ""
        if title in blocking_by_title:
            top = " | Principales: " + "; ".join(
                f"{f.severity} {f.title[:60]} @ {f.location[:70]}" for f in blocking_by_title[title][:3])
        print(f"::error title={esc('Quality Gate - ' + title, True)}::{esc(status + top)}")
    base = Path(args.reports)
    files = sorted(str(p.relative_to(base)).replace("\\", "/") for p in base.rglob("*") if p.is_file()) if base.exists() else []
    print(f"::notice title={esc('Quality Gate - reportes encontrados (' + str(len(files)) + ')', True)}::"
          f"{esc(', '.join(files[:40]) or '(ninguno: la carpeta no existe o esta vacia)')}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reports", default="reports", help="carpeta raiz donde buscar los reportes (recursivo)")
    p.add_argument("--fail-on", default=os.environ.get("QG_FAIL_ON", "HIGH"), choices=["CRITICAL", "HIGH", "MEDIUM"],
                   help="severidad minima que bloquea (por defecto HIGH, incluye CRITICAL)")
    p.add_argument("--needs-json", default=os.environ.get("NEEDS_JSON"), help="toJSON(needs) de GitHub Actions")
    p.add_argument("--no-needs", action="store_true", help="no exigir resultados de jobs (uso local)")
    p.add_argument("--odc-expected", default=os.environ.get("ODC_EXPECTED", "false"),
                   help="true si el job de Dependency-Check debe haber corrido (nightly)")
    p.add_argument("--allow-missing", action="store_true", help="no fallar si falta algun reporte (uso local)")
    p.add_argument("--summary-file", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    p.add_argument("--max-listed", type=int, default=8, help="hallazgos listados por herramienta")
    args = p.parse_args()
    args.odc_expected = str(args.odc_expected).lower() == "true"

    needs = None
    if not args.no_needs:
        if not args.needs_json:
            p.error("falta NEEDS_JSON / --needs-json (o usa --no-needs en local)")
        needs = json.loads(args.needs_json)

    rows, details, failures = evaluate(args, needs)
    text = render(args, rows, details, failures)
    print(text)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(text)
    Path("quality-gate-summary.md").write_text(text, encoding="utf-8")
    annotate(args, rows, details, failures, text)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
