#!/usr/bin/env python3
"""Carga los reportes del pipeline en DefectDojo por su API v2. Es opcional: tambien se puede hacer a mano desde la
interfaz (Engagement > Import Scan Results); ver docs/defectdojo.md.

Uso (el token se lee SOLO de la variable de entorno, nunca por argumento, para que no quede en el historial):

    export DD_API_TOKEN=...            # PowerShell: $env:DD_API_TOKEN = "..."
    gh run download <id-de-la-ejecucion> --dir reports
    python scripts/defectdojo_import.py --reports reports --engagement "CI/CD main" \\
        --branch main --commit <sha> --build-id <id-de-la-ejecucion>

Cada reporte se envia a /api/v2/reimport-scan/ con auto_create_context: la primera vez DefectDojo crea el Product Type,
el Product, el Engagement y el Test; las veces siguientes reimporta en el MISMO Test y cierra los hallazgos que ya no
aparecen en el reporte (asi se ve el antes/despues). Solo usa la libreria estandar de Python.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

# archivo del pipeline, tipo de scan en DefectDojo, titulo del Test
REPORTS = [
    ("semgrep-report.json", "Semgrep JSON Report", "Semgrep (SAST)"),
    ("trivy-report.json", "Trivy Scan", "Trivy - imagen del proyecto"),
    ("sca-report.json", "Trivy Scan", "Trivy - SBOM (SCA)"),
    ("dependency-check-report.xml", "Dependency Check Scan", "OWASP Dependency-Check (SCA)"),
    ("spotbugsXml.xml", "SpotBugs Scan", "SpotBugs + FindSecBugs"),
    ("java.sarif", "SARIF", "CodeQL (SAST)"),
]
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def multipart(fields, filename, content):
    """Arma un cuerpo multipart/form-data (campos de texto + el archivo en 'file')."""
    boundary = uuid.uuid4().hex
    body = b""
    for key, value in fields.items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode("utf-8")
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
             "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8") + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode("utf-8")
    return f"multipart/form-data; boundary={boundary}", body


def send(url, token, fields, path):
    content_type, body = multipart(fields, path.name, path.read_bytes())
    request = urllib.request.Request(
        f"{url}/api/v2/reimport-scan/", data=body, method="POST",
        headers={"Authorization": f"Token {token}", "Content-Type": content_type, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310 (URL validada en main)
        return json.loads(response.read().decode("utf-8"))


def total(counts):
    """La API devuelve contadores por severidad y un 'total' que a su vez es un diccionario con 'total'."""
    value = (counts or {}).get("total")
    return value.get("total", 0) if isinstance(value, dict) else (value or 0)


def summarize(result):
    stats = result.get("statistics") or {}
    delta = stats.get("delta") or {}
    parts = []
    if delta:
        for key, label in (("created", "nuevos"), ("closed", "cerrados"), ("reactivated", "reactivados"),
                           ("untouched", "sin cambios")):
            parts.append(f"{label}: {total(delta.get(key))}")
    after = (stats.get("after") or {}).get("total") or {}
    if isinstance(after, dict) and after:
        parts.append(f"activos ahora: {after.get('active', '?')}")
    return ", ".join(parts) or "sin estadisticas"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Carga los reportes del pipeline en DefectDojo (API v2).")
    ap.add_argument("--reports", default="reports", help="carpeta con los artifacts descargados (se busca recursivo)")
    ap.add_argument("--url", default=os.environ.get("DD_URL", "http://localhost:8080"), help="URL de DefectDojo (o DD_URL)")
    ap.add_argument("--product-type", default="Laboratorio DevSecOps")
    ap.add_argument("--product", default="spring-boot-webapi-secure")
    ap.add_argument("--engagement", default="CI/CD main", help="Engagement; se crea de tipo CI/CD si no existe")
    ap.add_argument("--branch", default="", help="rama analizada (queda en el Test)")
    ap.add_argument("--commit", default="", help="commit analizado (queda en el Test)")
    ap.add_argument("--build-id", default="", help="id de la ejecucion de GitHub Actions (queda en el Test)")
    ap.add_argument("--dry-run", action="store_true", help="solo muestra que enviaria, sin llamar a la API")
    args = ap.parse_args()

    url = args.url.rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        sys.exit(f"URL invalida: {url}")
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
        sys.exit("Por seguridad el token no se envia por HTTP a un servidor remoto: usa https o una instancia local.")
    token = os.environ.get("DD_API_TOKEN", "")
    if not token and not args.dry_run:
        sys.exit("Falta la variable de entorno DD_API_TOKEN (DefectDojo > menu del usuario > API v2 Key).")

    root = Path(args.reports)
    if not root.is_dir():
        sys.exit(f"No existe la carpeta de reportes: {root}")

    failures = missing = 0
    for filename, scan_type, title in REPORTS:
        found = sorted(root.rglob(filename))
        if not found:
            print(f"- {title}: no hay '{filename}' en {root} (se omite)")
            missing += 1
            continue
        path = found[0]
        extra = f" (hay {len(found)} copias; uso {path.parent.name}/)" if len(found) > 1 else ""
        fields = {
            "scan_type": scan_type, "test_title": title, "auto_create_context": "true",
            "product_type_name": args.product_type, "product_name": args.product, "engagement_name": args.engagement,
            "active": "true", "minimum_severity": "Info",
        }
        for key, value in (("branch_tag", args.branch), ("commit_hash", args.commit), ("build_id", args.build_id)):
            if value:
                fields[key] = value
        if args.dry_run:
            print(f"- {title}: enviaria {path} como '{scan_type}' a {url}{extra}")
            continue
        try:
            result = send(url, token, fields, path)
            print(f"- {title}: OK, test {result.get('test_id')} ({summarize(result)}){extra}")
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", errors="replace")[:300]
            print(f"- {title}: ERROR HTTP {err.code}: {detail}")
            failures += 1
        except urllib.error.URLError as err:
            print(f"- {title}: no se pudo conectar con {url}: {err.reason}")
            failures += 1
    print(f"Listo: {len(REPORTS) - missing - failures} cargados, {missing} omitidos, {failures} con error.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
