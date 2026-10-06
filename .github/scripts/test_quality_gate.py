#!/usr/bin/env python3
"""Pruebas del Quality Gate (solo libreria estandar):  python3 -m unittest discover -s .github/scripts -v

Cada prueba escribe reportes sinteticos en una carpeta temporal y comprueba que el gate apruebe o rechace
segun la politica: HIGH y CRITICAL bloquean, MEDIUM y LOW no; un job que falla o que no deja su reporte
tambien bloquea; la imagen ignora vulnerabilidades sin correccion y bloquea secretos.
"""
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import quality_gate as qg

OK_JOBS = {j: {"result": "success"} for j in (
    "build-and-test", "docker-smoke-test", "sast-semgrep", "sast-codeql", "static-analysis",
    "sca-sbom", "image-scan")}


def semgrep(*severities):
    return {"results": [{"check_id": f"regla-{i}", "path": "A.java", "start": {"line": i + 1},
                         "extra": {"severity": s}} for i, s in enumerate(severities)]}


def trivy(*vulns):
    """vulns: (id, severidad, version_corregida o None)"""
    return {"SchemaVersion": 2, "Results": [{"Target": "app", "Vulnerabilities": [
        {"VulnerabilityID": v, "PkgName": "lib", "InstalledVersion": "1.0", "Severity": s,
         **({"FixedVersion": fix} if fix else {})} for v, s, fix in vulns]}]}


SARIF_CLEAN = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}
SPOTBUGS_CLEAN = "<BugCollection/>"


class GateTest(unittest.TestCase):
    def run_gate(self, reports, needs=OK_JOBS, odc=False, allow_missing=False, fail_on="HIGH"):
        """reports: {nombre_de_archivo: dict/list (JSON) o str (XML)}; devuelve (filas, detalles, fallos, inventario)."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            base_reports = {"semgrep-report.json": semgrep(), "java.sarif": SARIF_CLEAN, "spotbugsXml.xml": SPOTBUGS_CLEAN,
                            "sca-report.json": trivy(), "trivy-report.json": trivy()}
            base_reports.update(reports)
            for name, content in base_reports.items():
                if content is None:
                    continue
                folder = base / name.split(".")[0]  # download-artifact crea una carpeta por artefacto
                folder.mkdir(exist_ok=True)
                text = content if isinstance(content, str) else json.dumps(content)
                (folder / name).write_text(text, encoding="utf-8")
            args = Namespace(reports=str(base), fail_on=fail_on, odc_expected=odc, allow_missing=allow_missing, max_listed=8)
            return qg.evaluate(args, needs)

    def test_everything_clean_passes(self):
        _rows, _details, failures, inventory = self.run_gate({})
        self.assertEqual(failures, [])
        self.assertEqual(len(inventory), 5)  # los cinco reportes de un CI normal

    def test_medium_and_low_do_not_block(self):
        _r, _d, failures, _i = self.run_gate({"semgrep-report.json": semgrep("WARNING", "INFO"),
                                              "sca-report.json": trivy(("CVE-1", "MEDIUM", "2.0"), ("CVE-2", "LOW", "2.0"))})
        self.assertEqual(failures, [])

    def test_semgrep_error_blocks(self):
        _r, details, failures, _i = self.run_gate({"semgrep-report.json": semgrep("ERROR", "WARNING")})
        self.assertEqual(len(failures), 1)
        self.assertIn("Semgrep", failures[0])
        self.assertEqual(len(details[0][1]), 1)

    def test_legacy_semgrep_file_name_is_still_read(self):
        _r, _d, failures, _i = self.run_gate({"semgrep-report.json": None, "semgrep-results.json": semgrep("ERROR")})
        self.assertEqual(len(failures), 1)

    def test_image_scan_ignores_unfixed_vulnerabilities(self):
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": trivy(("CVE-9", "CRITICAL", None))})
        self.assertEqual(failures, [])

    def test_image_scan_blocks_fixable_high(self):
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": trivy(("CVE-9", "HIGH", "1.2.3"))})
        self.assertEqual(len(failures), 1)
        self.assertIn("imagen", failures[0])

    def test_sbom_scan_counts_unfixed_vulnerabilities(self):
        _r, _d, failures, _i = self.run_gate({"sca-report.json": trivy(("CVE-9", "HIGH", None))})
        self.assertEqual(len(failures), 1)

    def test_image_secret_blocks(self):
        report = {"SchemaVersion": 2, "Results": [{"Target": "app/config", "Secrets": [
            {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 4}]}]}
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": report})
        self.assertEqual(len(failures), 1)

    def test_failed_job_blocks_even_with_clean_report(self):
        needs = {**OK_JOBS, "image-scan": {"result": "failure"}}
        _r, _d, failures, _i = self.run_gate({}, needs=needs)
        self.assertTrue(any("imagen" in f and "failure" in f for f in failures))

    def test_missing_report_of_a_successful_job_blocks(self):
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": None})
        self.assertTrue(any("no se encontro el reporte 'trivy-report.json'" in f for f in failures))

    def test_missing_report_is_tolerated_in_local_mode(self):
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": None}, needs=None, allow_missing=True)
        self.assertEqual(failures, [])

    def test_corrupt_report_blocks(self):
        _r, _d, failures, _i = self.run_gate({"trivy-report.json": "esto no es json"})
        self.assertTrue(any("no se pudo leer" in f for f in failures))

    def test_dependency_check_only_when_expected(self):
        odc = {"dependencies": [{"fileName": "x.jar", "vulnerabilities": [{"name": "CVE-1", "severity": "HIGH"}]}]}
        rows, _d, failures, _i = self.run_gate({"dependency-check-report.json": odc}, odc=False)
        self.assertEqual(failures, [])
        self.assertTrue(any(status == "no aplica (solo nightly)" for _t, _c, status in rows))
        needs = {**OK_JOBS, "sca-dependency-check": {"result": "success"}}
        _r, _d, failures, _i = self.run_gate({"dependency-check-report.json": odc}, needs=needs, odc=True)
        self.assertEqual(len(failures), 1)

    def test_fail_on_critical_lets_high_through(self):
        _r, _d, failures, _i = self.run_gate({"semgrep-report.json": semgrep("ERROR")}, fail_on="CRITICAL")
        self.assertEqual(failures, [])

    def test_spotbugs_priority_one_blocks(self):
        xml = ('<BugCollection><BugInstance type="SQL_INJECTION" priority="1" rank="3">'
               '<Class classname="a.B"/><SourceLine start="7"/></BugInstance></BugCollection>')
        _r, _d, failures, _i = self.run_gate({"spotbugsXml.xml": xml})
        self.assertEqual(len(failures), 1)

    def test_codeql_security_severity_blocks_from_seven(self):
        def sarif(score):
            return {"runs": [{"tool": {"driver": {"rules": [{"id": "java/sqli", "properties": {"security-severity": score}}]}},
                              "results": [{"ruleId": "java/sqli", "locations": []}]}]}
        _r, _d, failures, _i = self.run_gate({"java.sarif": sarif("6.9")})
        self.assertEqual(failures, [])
        _r, _d, failures, _i = self.run_gate({"java.sarif": sarif("7.0")})
        self.assertEqual(len(failures), 1)


if __name__ == "__main__":
    unittest.main()
