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

## Pipelines de seguridad (Laboratorio 3)

| Workflow | Cuándo corre | Qué hace |
|---|---|---|
| `ci-sec.yml` (CI) | push a `feature/**`, `bugfix/**`, `hotfix/**` y PR a `main`/`develop` | Build & Test, CodeQL, Semgrep, SpotBugs + FindSecBugs, SBOM + Trivy, prueba de humo de la imagen y **Quality Gate** |
| `ci-cd-sec.yml` (CI/CD) | push a `main` y `develop` | El CI completo; si el gate aprueba: imagen Docker, Trivy, publicación en GHCR y despliegue en EC2 |
| `ci-sec-nightly.yml` | cada día 20:55 (La Paz) y manual | El CI completo + OWASP Dependency-Check (necesita el secret `NVD_API_KEY`) |

Los jobs viven en `.github/workflows/_ci-core.yml` (workflow reutilizable). Todas las acciones están
fijadas por SHA; Dependabot propone las actualizaciones.

**Quality Gate.** `.github/scripts/quality_gate.py` descarga los reportes de los escáneres (SARIF de
CodeQL, JSON de Semgrep, XML de SpotBugs, JSON de Trivy y de Dependency-Check), cuenta hallazgos por
severidad y **falla el pipeline** si hay alguno `HIGH` o `CRITICAL`, si un job falló o si un job terminó
bien pero no dejó su reporte. El resultado queda en el *Job Summary* de la ejecución.

### Ejecutar los escáneres en local (Windows, PowerShell)

```powershell
.\mvnw.cmd -B clean verify                                   # compilar + pruebas + JaCoCo
$env:NVD_API_KEY = "<tu clave NVD>"                          # solo en memoria; nunca en el repo
.\mvnw.cmd -B org.owasp:dependency-check-maven:check "-Dformats=HTML,JSON"
.\mvnw.cmd -B clean compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs
semgrep scan --config auto --config .semgrep.yml --metrics=on --json-output=target\semgrep\semgrep-results.json src\main\java
python .github\scripts\quality_gate.py --reports target --no-needs --allow-missing
```

### Secrets y variables del repositorio

| Nombre | Tipo | Para qué |
|---|---|---|
| `NVD_API_KEY` | Secret | Descarga de la base NVD (nightly). Pídela gratis en https://nvd.nist.gov/developers/request-an-api-key |
| `AWS_ROLE_ARN`, `EC2_INSTANCE_ID`, `AWS_REGION` | Variables | Despliegue en EC2 por SSM con OIDC (sin claves en GitHub). Si no existen, el job de deploy se omite |
