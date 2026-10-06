# Spring Boot DevSecOps Lab

Aplicacion deliberadamente vulnerable para prácticas controladas de SAST, SCA,
secret scanning, análisis de contenedores y DAST.

> **Advertencia:** ejecutar únicamente en `localhost` o en una red de laboratorio
> aislada. No desplegar en Internet ni reutilizar credenciales reales.

## Requisitos

- JDK 21
- Maven 3.9+
- Docker, opcional
- Semgrep, para el análisis local

## Iniciar la aplicación

```bash
mvn clean verify
mvn spring-boot:run
```

La aplicación estará disponible en `http://localhost:8080`.

## Endpoints del laboratorio

```text
GET  /api/products/search?name=Laptop
POST /api/comments/preview
GET  /api/admin/users/1
POST /api/auth/login
```

Ejemplo para la vista previa:

```bash
curl -X POST http://localhost:8080/api/comments/preview \
  -H "Content-Type: application/json" \
  -d '{"comment":"Comentario de prueba"}'
```

Ejemplo de autenticación:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario","password":"prueba"}'
```

## Semgrep local

```bash
semgrep scan --config auto --config .semgrep.yml src/main/java
```

El docente dispone de `docs/GUIA-DOCENTE.md`, que contiene el catálogo de
hallazgos y las pruebas sugeridas. Se recomienda entregar inicialmente a los
estudiantes el resto del repositorio sin dicho documento.

## Pipelines de seguridad (Laboratorios 3 y final)

| Workflow | Cuándo corre | Qué hace |
|---|---|---|
| `ci-sec.yml` (CI) | push a `feature/**`, `bugfix/**`, `hotfix/**` y PR a `main`/`develop` | Build & Test, CodeQL, Semgrep, SpotBugs + FindSecBugs, SBOM + Trivy, **análisis de la imagen del proyecto con Trivy**, prueba de humo de la imagen y **Quality Gate** |
| `ci-cd-sec.yml` (CI/CD) | push a `main` y `develop` | El CI completo; si el gate aprueba: imagen Docker, Trivy (SARIF y JSON), publicación en GHCR y despliegue en EC2 |
| `ci-sec-nightly.yml` | cada día 20:55 (La Paz) y manual | El CI completo + OWASP Dependency-Check (necesita el secret `NVD_API_KEY`) |

Los jobs viven en `.github/workflows/_ci-core.yml` (workflow reutilizable). Todas las acciones están
fijadas por SHA; Dependabot propone las actualizaciones.

**Quality Gate.** `.github/scripts/quality_gate.py` descarga los reportes de los escáneres (SARIF de
CodeQL, JSON de Semgrep, XML de SpotBugs, JSON de Trivy sobre el SBOM y sobre la imagen, y JSON de Dependency-Check), cuenta hallazgos por
severidad y **falla el pipeline** si hay alguno `HIGH` o `CRITICAL`, si un job falló o si un job terminó
bien pero no dejó su reporte. El resultado queda en el *Job Summary* de la ejecución.

### Ejecutar los escáneres en local (Windows, PowerShell)

```powershell
.\mvnw.cmd -B clean verify                                   # compilar + pruebas + JaCoCo
$env:NVD_API_KEY = "<tu clave NVD>"                          # solo en memoria; nunca en el repo
.\mvnw.cmd -B org.owasp:dependency-check-maven:check        # falla con CVSS >= 7; genera HTML, JSON y XML (ver pom.xml)
.\mvnw.cmd -B clean compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs "-Dspotbugs.sarifOutput=true"
semgrep scan --config auto --config .semgrep.yml --metrics=on --json-output=target\semgrep\semgrep-report.json src\main\java
python .github\scripts\quality_gate.py --reports target --no-needs --allow-missing
```

### Reportes JSON, análisis de la imagen y DefectDojo (Laboratorio Final)

Cada control del workflow deja su reporte como *artifact* de la ejecución (30 días), **aunque el pipeline se bloquee**:

| Control | Job | Reporte | Artifact | Parser de DefectDojo |
|---|---|---|---|---|
| SAST | `SAST - Semgrep` | `semgrep-report.json` (y `.sarif`) | `semgrep-reports` | Semgrep JSON Report |
| Análisis de la **imagen del proyecto** (se construye con el `Dockerfile` de este repo) | `Image Scan - Trivy` | `trivy-report.json` | `trivy-image-report` | Trivy Scan |
| SCA (SBOM CycloneDX) | `SCA - SBOM + Trivy` | `sca-report.json` | `sca-sbom` | Trivy Scan |
| SCA (nightly) | `SCA - OWASP Dependency-Check` | `dependency-check-report.xml` y `.json` | `dependency-check-report` | Dependency Check Scan (solo XML) |
| Estático | `Static Analysis (SpotBugs)` | `spotbugsXml.xml` y `spotbugsSarif.json` | `spotbugs-reports` | SpotBugs Scan |
| SAST | `SAST - CodeQL` | `java.sarif` | `codeql-sarif` | SARIF |
| Imagen publicada (CD) | `Docker Build → Scan → Push` | `trivy-report.json` | `trivy-image-release` | Trivy Scan |

El Quality Gate lee los JSON, ignora en la imagen las vulnerabilidades sin corrección disponible (mismo criterio que el
gate del CD) y lista al final del resumen los reportes que analizó. Los riesgos aceptados de Trivy están en
`.trivyignore.yaml` (con caducidad), el mismo registro que `dependency-check-suppressions.xml`; el análisis por CVE está en
`evidencias/sca/riesgos-aceptados.md`. Las imágenes de Trivy se usan fijadas por digest.

**Cómo se obtiene y se despliega la versión construida.** El job de publicación construye la imagen, la escanea y, si
el gate aprueba, la sube a GHCR con las etiquetas `sha-<commit>`, `<rama>` y `latest` (solo `main`). Su resumen imprime la
referencia inmutable `ghcr.io/<repo>@sha256:...`; el job `Deploy to EC2` despliega **esa misma referencia** por SSH
(no la etiqueta). En cualquier equipo con Docker: `docker pull <referencia>`.

**DefectDojo.** `docs/defectdojo.md` explica cómo levantar la instancia (Docker Compose), cómo organizar Product, Engagement
y Tests, y cómo importar estos reportes a mano o con `scripts/defectdojo_import.py` (opcional, por API).

### Secrets y variables del repositorio

| Nombre | Tipo | Para qué |
|---|---|---|
| `NVD_API_KEY` | Secret | Descarga de la base NVD (nightly). Pídela gratis en https://nvd.nist.gov/developers/request-an-api-key |
| `EC2_SSH_KEY` | Secret | Llave **privada de despliegue** (dedicada, no tu llave personal). En el servidor solo puede ejecutar `deploy-webapi` |
| `EC2_HOST`, `EC2_USER` (opcional, por defecto `deploy`), `EC2_KNOWN_HOSTS` | Variables | Servidor EC2 y su huella SSH (salida de `ssh-keyscan -t ed25519 <host>`). Si `EC2_HOST` no existe, el job de deploy se omite |

El servidor se prepara una sola vez con `infra/ec2-bootstrap.sh` (Docker, usuario `deploy`, llave con `command=`,
sshd endurecido). `deploy/remote-deploy.sh` es el script que se instala como `deploy-webapi`.
