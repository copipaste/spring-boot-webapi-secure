# DefectDojo: instancia propia, importación y revisión de hallazgos

Guía del Laboratorio Final. DefectDojo reúne los reportes JSON/XML que genera el pipeline y permite revisarlos, clasificarlos
y llevar el tratamiento de cada hallazgo. Versión usada: **3.4.0**.

## 1. Levantar tu instancia (Docker Compose)

Requisitos (según la documentación de DefectDojo): Docker con Compose, 2 vCPU, **8 GB de RAM** para la máquina virtual
de Docker (en Docker Desktop: Settings > Resources) y 10 GB de disco.

```bash
git clone --depth 1 --branch 3.4.0 https://github.com/DefectDojo/django-DefectDojo.git defectdojo
cd defectdojo
```

Crea el archivo `.env` junto a `docker-compose.yml` (no lo subas a ningún repositorio):

```bash
# Descarga las imágenes directamente de Docker Hub: por defecto pasan por registry.defectdojo.com, que registra tu IP
DD_IMAGE_REGISTRY=docker.io
DJANGO_VERSION=3.4.0
NGINX_VERSION=3.4.0
# Cambia estas dos claves por valores propios (la clave AES debe tener 32 caracteres)
DD_SECRET_KEY=<cadena aleatoria larga>
DD_CREDENTIAL_AES_256_KEY=<32 caracteres aleatorios>
```

Opcional pero recomendado: publicar DefectDojo solo en tu equipo. Crea `docker-compose.override.yml`:

```yaml
services:
  nginx:
    ports: !override
      - "127.0.0.1:${DD_PORT:-8080}:8080"
```

Arranca y espera unos minutos (la primera vez corre las migraciones):

```bash
docker compose up -d
docker compose logs initializer | grep "Admin password:"     # contraseña inicial del usuario admin
```

Abre http://localhost:8080 e ingresa con `admin`. Cambia la contraseña: `docker compose exec uwsgi ./manage.py changepassword admin`.
Para detener: `docker compose stop`; para borrar todo, incluidos los datos: `docker compose down --volumes`.

## 2. Cómo se organiza el proyecto

| Nivel en DefectDojo | Qué se usa aquí |
|---|---|
| Product Type | `Laboratorio DevSecOps` |
| Product | `spring-boot-webapi-secure` |
| Engagement | `CI/CD main` (tipo CI/CD): agrupa las cargas del pipeline |
| Test | Uno por herramienta: Semgrep, Trivy imagen, Trivy SBOM, Dependency-Check, SpotBugs, CodeQL |

El "antes" se importa en cada Test y el "después" se **reimporta en el mismo Test**: DefectDojo marca como cerrados
(Mitigated) los hallazgos que ya no aparecen, que es la comparación antes/después. Cada Test conserva rama, commit y
número de ejecución de GitHub Actions, que sirven para identificar la evidencia.

## 3. Qué reporte va con qué parser

| Reporte del pipeline | Tipo de scan en DefectDojo | Notas |
|---|---|---|
| `semgrep-report.json` | Semgrep JSON Report | ERROR se vuelve High, WARNING Medium, INFO Low |
| `trivy-report.json` (imagen) | Trivy Scan | JSON de `trivy image --format json` (SchemaVersion 2); UNKNOWN se vuelve Info |
| `sca-report.json` (SBOM) | Trivy Scan | Mismo parser |
| `dependency-check-report.xml` | Dependency Check Scan | **Solo XML**; el JSON del pipeline no se puede importar |
| `spotbugsXml.xml` | SpotBugs Scan | XML; `spotbugsSarif.json` iría por el parser SARIF |
| `java.sarif` (CodeQL) | SARIF | |

Un reporte sin parser compatible (por ejemplo, de una herramienta que la versión de DefectDojo no soporte) se adjunta
al informe explicando la limitación.

**Dependency-Check y las supresiones.** El parser importa también las vulnerabilidades suprimidas en
`dependency-check-suppressions.xml` (los 15 CVE de Spring aceptados): las marca con la etiqueta `suppressed` y copia la
justificación del archivo en el campo *Mitigation*. Conviene registrarlas en DefectDojo como **Risk Accepted** para que
queden diferenciadas de los hallazgos activos.

## 4. Importar los reportes

**Descargar los artifacts** de una ejecución (cada uno es un ZIP; con `gh` se descargan todos):

```bash
gh run list --workflow "CI - Spring Boot DevSecOps" --limit 5
gh run download <id-de-la-ejecucion> --dir reports
```

**A mano (interfaz):** Product > Engagement > *Add Tests* / **Import Scan Results** > elegir el *Scan type* de la tabla,
seleccionar el archivo y *Import*. Para cargar de nuevo el mismo reporte actualizado, abre el Test y usa **Re-Upload Scan**.

**Por API (opcional):** copia tu clave desde el menú del usuario > *API v2 Key* y ejecuta:

```bash
export DD_API_TOKEN=<tu clave>        # PowerShell: $env:DD_API_TOKEN = "<tu clave>"
python scripts/defectdojo_import.py --reports reports --engagement "CI/CD main" \
    --branch main --commit <sha> --build-id <id-de-la-ejecucion>
```

El script usa `reimport-scan` con creación automática de Product, Engagement y Test, no acepta enviar el token por HTTP
a un servidor remoto y nunca imprime el token. `--dry-run` muestra qué enviaría.

## 5. Revisar, clasificar y tratar

Para cada hallazgo (*Findings* > abrir el hallazgo):

| Decisión del equipo | Cómo se marca en DefectDojo |
|---|---|
| **Confirmado** | *Active* + *Verified*; añade una nota con la evidencia y la acción de tratamiento |
| **Pendiente de investigación** | *Under Review* + nota con lo que falta comprobar |
| **Posible falso positivo** | *False Positive* + nota con el motivo técnico |
| **Duplicado** | *Duplicate* (por ejemplo, dos reglas que marcan la misma línea) |
| **Riesgo aceptado** | *Risk Accepted* (o *Risk Acceptance* con fecha de caducidad) + justificación |
| **Corregido** | Se reimporta el reporte posterior: el hallazgo queda *Mitigated* |

Ajusta la **prioridad** (severidad, y *Planned Remediation* si aplica) justificándola en la nota: componente afectado,
exposición real en este proyecto y existencia de corrección.

## 6. Seguridad

- La clave de la API, la contraseña de `admin` y el `.env` no se suben al repositorio ni aparecen en capturas o en el PDF.
- DefectDojo se publica solo en `127.0.0.1`; si lo expones en una red, pon HTTPS delante.
- Los reportes pueden contener rutas, versiones y fragmentos de código: trátalos como información interna.
