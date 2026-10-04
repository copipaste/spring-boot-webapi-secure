# Taller práctico: SCA, SBOM y actualización de dependencias

**Módulo:** DevSecOps  
**Proyecto:** laboratorio Spring Boot con Maven  
**Fecha:** 30 de septiembre de 2026  
**Duración:** 3 horas, de 19:00 a 22:00  
**Modalidad:** trabajo guiado por grupos

## 1. Objetivo y resultado esperado

Implementar un flujo que inventaríe las dependencias del proyecto, detecte vulnerabilidades conocidas y compruebe una actualización mediante GitHub Actions.

Al terminar, el grupo tendrá un SBOM en formato CycloneDX, un reporte SCA, un pipeline que falla ante vulnerabilidades HIGH o CRITICAL y una configuración de Dependabot.

El ejercicio sigue este ciclo:

1. Identificar dependencias directas y transitivas.
2. Generar el inventario SBOM.
3. Analizarlo con Trivy.
4. Ejecutar el análisis y el bloqueo en GitHub Actions.
5. Actualizar una dependencia y comparar resultados.

### Herramientas y responsabilidades

| Herramienta | Función |
|---|---|
| Maven | Resolver dependencias, compilar y ejecutar pruebas. |
| CycloneDX Maven Plugin | Generar el SBOM del proyecto. |
| Trivy | Buscar vulnerabilidades conocidas de los componentes del SBOM. |
| GitHub Actions | Ejecutar el proceso por push y pull request. |
| Dependabot | Proponer actualizaciones mediante pull requests. |
| Snyk, opcional | Comparar los resultados del análisis de dependencias. |

**Un SBOM es un inventario, no un certificado de seguridad.** SCA relaciona los componentes y sus versiones con información de vulnerabilidades. Un hallazgo por versión tampoco demuestra por sí solo que un endpoint sea explotable: hace falta revisar el uso del componente.

## 2. Agenda

| Horario | Actividad |
|---|---|
| 19:00–19:10 | Preparar proyecto, rama y ejecución inicial. |
| 19:10–19:30 | Explorar el árbol de dependencias. |
| 19:30–19:55 | Configurar CycloneDX y generar el SBOM. |
| 19:55–20:20 | Introducir el caso didáctico y analizar el SBOM. |
| 20:20–20:30 | Pausa. |
| 20:30–21:00 | Implementar el workflow y descargar evidencias. |
| 21:00–21:20 | Comprobar el quality gate. |
| 21:20–21:40 | Configurar Dependabot y preparar la actualización. |
| 21:40–21:55 | Corregir, ejecutar pruebas y comparar. |
| 21:55–22:00 | Presentar evidencias y registrar pendientes. |

## 3. Requisitos y preparación

- Repositorio del laboratorio en GitHub y permiso para crear ramas y workflows.
- Git y Java compatibles con el proyecto.
- Maven instalado o Maven Wrapper incluido en el repositorio.
- Docker, solamente para ejecutar Trivy localmente. El runner de Actions ejecutará Docker aunque el participante no lo tenga.
- Acceso a Maven Central, al registro de imágenes y a las bases de vulnerabilidades.
- GitHub Actions habilitado y capacidad disponible para ejecutar jobs.

**Supuestos de esta guía:** `pom.xml` está en la raíz, el runner es GitHub.com y el proyecto usa Java 17. Si el proyecto usa Java 21 u otra versión, ajustar `java-version` en el workflow. Si está en un subdirectorio, adaptar los comandos, las rutas del SBOM y `directory` de Dependabot.

Los comandos locales se muestran para Bash, Git Bash o WSL. Con Maven Wrapper reemplazar `mvn` por `./mvnw`; en PowerShell, por `.\mvnw.cmd`.

**Preparación docente:** ejecutar previamente la guía en una copia del laboratorio y conservar un reporte de referencia. La versión real del proyecto y la base de vulnerabilidades pueden introducir hallazgos adicionales. Esta guía no presupone que el repositorio ya esté libre de vulnerabilidades.

## 4. Paso 1 — Preparar la rama y comprobar el proyecto

Abrir una terminal en la carpeta que contiene `pom.xml`:

```bash
git status
git switch -c lab/sca-sbom
java -version
mvn -version
mvn -B clean verify
```

Si existen cambios sin guardar, conservarlos antes de cambiar de rama. Resolver los errores de compilación o de pruebas antes de continuar. Si las pruebas requieren una base de datos, mantener la configuración de servicios que ya utiliza el CI del curso.

**Evidencia:** registrar el commit de partida y el resultado de `verify`.

```bash
git rev-parse HEAD
```

## 5. Paso 2 — Explorar dependencias

```bash
mvn dependency:tree
mvn dependency:tree -DoutputFile=target/dependency-tree.txt
```

Seleccionar una dependencia declarada en el POM y dos que aparezcan por medio de ella. Completar:

| Dependencia | Versión resuelta | Directa/transitiva | Quién la incorpora |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Consultar `dependencyManagement` y el parent de Spring Boot. Una dependencia sin `<version>` puede recibir su versión del BOM o del parent; no significa que no tenga versión.

**Control:** el grupo puede explicar por qué el árbol tiene más componentes que la lista de dependencias explícitas de `pom.xml`.

## 6. Paso 3 — Configurar CycloneDX

Agregar el siguiente plugin dentro de `<build><plugins>` del `pom.xml`. Conservar el plugin de Spring Boot y los plugins existentes. Si ya existe `<build>`, editarlo; no crear otro bloque duplicado.

```xml
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <version>2.9.3</version>
    <configuration>
        <schemaVersion>1.6</schemaVersion>
        <outputFormat>json</outputFormat>
        <outputName>bom</outputName>
        <includeBomSerialNumber>true</includeBomSerialNumber>
        <includeCompileScope>true</includeCompileScope>
        <includeRuntimeScope>true</includeRuntimeScope>
        <includeProvidedScope>true</includeProvidedScope>
        <includeSystemScope>false</includeSystemScope>
        <includeTestScope>false</includeTestScope>
    </configuration>
</plugin>
```

Se excluyen las dependencias exclusivas de pruebas para concentrar el taller en la aplicación. Esto delimita el inventario: el SBOM no representa todas las herramientas del entorno de desarrollo ni todas las bibliotecas del sistema operativo.

Generar el SBOM con una versión explícita del plugin:

```bash
mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom
```

Abrir `target/bom.json` en el editor. Identificar:

- `bomFormat` y `specVersion`: formato y versión del estándar.
- `metadata.component`: aplicación inventariada.
- `components`: componentes con nombre, grupo, versión e identificadores.
- `purl`: identificador de paquete, cuando esté disponible.
- `dependencies`: relaciones entre componentes.

**Control:** localizar una dependencia transitiva del paso anterior dentro del SBOM.

> `makeAggregateBom` también permite inventariar proyectos Maven con múltiples módulos. Para este taller se analiza el SBOM agregado de la raíz.

## 7. Paso 4 — Agregar un caso didáctico vulnerable

Dentro de `<dependencies>`, agregar esta dependencia **solo al laboratorio**. Si ya está declarada, editar su versión en lugar de duplicarla:

```xml
<!-- Dependencia temporal para observar el análisis SCA del laboratorio. -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.9</version>
</dependency>
```

Apache Commons Text 1.9 está afectado por CVE-2022-42889. La posibilidad de explotación depende del uso de la API de interpolación con entradas no confiables. El ejercicio no necesita agregar un endpoint ni ejecutar una explotación: se observará un hallazgo de dependencia.

```bash
mvn -B clean verify
mvn dependency:tree -Dincludes=org.apache.commons:commons-text
mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom
```

**Control:** `bom.json` contiene `commons-text` con versión `1.9`. No reutilizar un SBOM generado antes de modificar el POM.

## 8. Paso 5 — Analizar el SBOM localmente

La guía fija Trivy `0.74.0` para utilizar la misma herramienta localmente y en Actions. Docker descargará la imagen en el primer uso:

```bash
docker pull aquasec/trivy:0.74.0
docker volume create devsecops-trivy-cache
```

Ejecutar desde la raíz del proyecto en Bash o WSL:

```bash
docker run --rm \
  -v "$PWD/target:/work" \
  -v devsecops-trivy-cache:/root/.cache/trivy \
  aquasec/trivy:0.74.0 sbom \
  --scanners vuln \
  --format table \
  /work/bom.json
```

Para guardar un reporte JSON completo:

```bash
docker run --rm \
  -v "$PWD/target:/work" \
  -v devsecops-trivy-cache:/root/.cache/trivy \
  aquasec/trivy:0.74.0 sbom \
  --scanners vuln \
  --format json \
  --output /work/sca-report.json \
  /work/bom.json
```

En PowerShell, ejecutar en una sola línea:

```powershell
docker run --rm -v "${PWD}/target:/work" -v devsecops-trivy-cache:/root/.cache/trivy aquasec/trivy:0.74.0 sbom --scanners vuln --format json --output /work/sca-report.json /work/bom.json
```

Si Git Bash transforma las rutas `/work`, usar WSL o PowerShell para los comandos Docker. Si el participante no tiene Docker, continuar con Actions y descargar los artifacts del paso siguiente.

Revisar el reporte y completar una ficha:

| Campo | Resultado |
|---|---|
| Componente y versión instalada | |
| CVE o identificador del hallazgo | |
| Severidad reportada | |
| Versión corregida, si aparece | |
| Directa o transitiva | |
| Uso del componente en nuestra aplicación | |
| Cambio propuesto y pruebas necesarias | |

La descarga inicial de bases puede tardar varios minutos. Un fallo de descarga no equivale a ausencia de vulnerabilidades.

## 9. Paso 6 — Implementar GitHub Actions

Crear `.github/workflows/sca-sbom.yml` con este contenido. Es un workflow independiente; puede coexistir con el workflow de Semgrep.

```yaml
name: SCA y SBOM

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  sca:
    name: SCA - SBOM y vulnerabilidades
    runs-on: ubuntu-latest
    timeout-minutes: 25

    env:
      TRIVY_IMAGE: aquasec/trivy:0.74.0

    steps:
      - name: Obtener codigo
        uses: actions/checkout@v4

      - name: Configurar Java
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
          cache: maven

      - name: Compilar y ejecutar pruebas
        run: mvn -B clean verify

      - name: Generar SBOM CycloneDX
        run: mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom

      - name: Validar presencia del SBOM
        run: test -s target/bom.json

      - name: Generar reporte SCA completo
        run: |
          mkdir -p "$RUNNER_TEMP/trivy-cache"
          docker run --rm \
            -v "$GITHUB_WORKSPACE/target:/work" \
            -v "$RUNNER_TEMP/trivy-cache:/root/.cache/trivy" \
            "$TRIVY_IMAGE" sbom \
            --scanners vuln \
            --exit-code 0 \
            --format json \
            --output /work/sca-report.json \
            /work/bom.json

      - name: Quality gate HIGH y CRITICAL
        run: |
          docker run --rm \
            -v "$GITHUB_WORKSPACE/target:/work" \
            -v "$RUNNER_TEMP/trivy-cache:/root/.cache/trivy" \
            "$TRIVY_IMAGE" sbom \
            --scanners vuln \
            --skip-db-update \
            --severity HIGH,CRITICAL \
            --exit-code 1 \
            --format table \
            --output /work/sca-gate.txt \
            /work/bom.json

      - name: Publicar evidencias
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sca-sbom-${{ github.run_id }}-${{ github.run_attempt }}
          path: |
            target/bom.json
            target/sca-report.json
            target/sca-gate.txt
          if-no-files-found: warn
          retention-days: 7
```

### Cómo funciona

1. `verify` conserva las pruebas del proyecto.
2. CycloneDX genera el inventario de dependencias resueltas.
3. Trivy produce el reporte completo sin bloquear por hallazgos en ese primer análisis.
4. Una segunda ejecución aplica el umbral HIGH/CRITICAL usando la base descargada durante el mismo job.
5. `--exit-code 1` hace fallar el paso cuando se encuentran vulnerabilidades del umbral.
6. `if: always()` intenta publicar los archivos disponibles incluso si el gate falla.

`--exit-code 0` no oculta errores técnicos del escáner; controla el resultado ante hallazgos. Un job rojo puede ser consecuencia de una vulnerabilidad, una prueba fallida o un problema de infraestructura: leer el paso que falló.

El reporte completo incluye severidades inferiores al umbral. La política no usa `--ignore-unfixed`: también bloquea hallazgos HIGH/CRITICAL sin corrección disponible.

**Adaptación:** cambiar Java al valor del proyecto y agregar los servicios que necesiten sus pruebas. Los ejemplos usan tags de Actions para facilitar la clase; para un pipeline mantenido, fijar acciones por SHA completo verificado e imágenes por digest, y revisar sus actualizaciones.

## 10. Paso 7 — Ejecutar y observar el bloqueo

```bash
git add pom.xml .github/workflows/sca-sbom.yml
git commit -m "lab: agregar SBOM y analisis SCA"
git push -u origin lab/sca-sbom
```

En GitHub:

1. Abrir **Actions** y seleccionar **SCA y SBOM**.
2. Revisar compilación, generación del SBOM y análisis.
3. Localizar el paso **Quality gate HIGH y CRITICAL**.
4. Descargar el artifact del resumen de la ejecución.
5. Abrir `sca-gate.txt` y `sca-report.json`.
6. Confirmar el hallazgo de `commons-text`; registrar otros hallazgos por separado.

**Resultado esperado:** el gate falla por la dependencia vulnerable si la base consultada identifica el caso y su severidad corresponde al umbral. Si no ocurre, revisar versión resuelta, contenido del SBOM y funcionamiento del análisis. No cambiar el umbral solo para fabricar el resultado.

Un workflow fallido no impide por sí solo que alguien fusione un PR. Para convertirlo en requisito de merge, configurar una regla de protección o ruleset de la rama principal y exigir el check **SCA - SBOM y vulnerabilidades**, según las opciones disponibles en el repositorio.

## 11. Paso 8 — Configurar Dependabot

Crear `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

Guardar:

```bash
git add .github/dependabot.yml
git commit -m "ci: configurar Dependabot para Maven y Actions"
git push
```

Para que GitHub active las actualizaciones de versiones, este archivo debe llegar a la **rama predeterminada**. Si el PR del laboratorio todavía está bloqueado, el docente puede incorporar únicamente la configuración mediante un PR separado, sin la dependencia vulnerable.

En **Settings**, buscar las opciones de seguridad y análisis del repositorio —los nombres de los menús pueden variar— y comprobar:

- Dependency graph habilitado.
- Dependabot alerts habilitado.
- Dependabot security updates habilitado.

### Distinguir tres funciones

| Función | Qué hace |
|---|---|
| Dependabot alerts | Notifica vulnerabilidades conocidas de dependencias detectadas. |
| Dependabot security updates | Intenta crear PRs de corrección cuando puede resolver una actualización. |
| Dependabot version updates | Busca versiones nuevas según `dependabot.yml`, aunque no exista una vulnerabilidad. |

Dependabot no es un paso del workflow. Sus PRs provocan la ejecución normal del CI. Las alertas y actualizaciones de seguridad no quedan habilitadas únicamente por crear el YAML.

No esperar un PR inmediato ni asumir que toda vulnerabilidad tendrá una actualización automática. Revisar los logs de Dependabot; si no llega un PR durante la clase, continuar con la corrección manual siguiente.

## 12. Paso 9 — Corregir la dependencia

Antes de editar, descargar las evidencias vulnerables y guardarlas con un nombre que identifique el commit.

Cambiar `commons-text` de `1.9` a `1.10.0` para observar la corrección histórica de CVE-2022-42889:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>
</dependency>
```

**Esta versión es el mínimo histórico para el caso seleccionado, no una recomendación de versión vigente ni una garantía de ausencia de otros hallazgos.** Revisar el reporte actual y, para mantener el componente, seleccionar una versión estable compatible que resuelva los hallazgos pertinentes. Como la dependencia se agregó únicamente para el laboratorio, eliminarla al cerrar la práctica es también una remediación válida, después de conservar la comparación.

```bash
mvn -B clean verify
mvn dependency:tree -Dincludes=org.apache.commons:commons-text
mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom
git add pom.xml
git commit -m "fix: actualizar Commons Text del laboratorio"
git push
```

Abrir un PR de `lab/sca-sbom` hacia la rama principal, si aún no existe, y revisar la nueva ejecución de Actions.

**Si se usa un PR de Dependabot:** inspeccionar el diff, comprobar versión resuelta y ejecutar el mismo CI antes de fusionar. Para dependencias transitivas administradas por Spring Boot, evaluar primero una actualización compatible del parent/BOM; sobrescribir versiones individualmente requiere verificar compatibilidad.

**Resultado esperado:** desaparece el hallazgo objetivo en el nuevo reporte. Si quedan otros HIGH/CRITICAL, el gate continuará rojo: registrar y corregir esos hallazgos o explicar el pendiente. No desactivar el control para obtener una captura verde.

## 13. Paso 10 — Comparar y entregar evidencias

Crear `evidencias/sca/comparacion.md` en el repositorio:

```markdown
# Comparación del análisis SCA

## Identificación

- Grupo:
- Repositorio:
- Commit anterior:
- Commit posterior:
- Ejecución anterior:
- Ejecución posterior:
- Pull request:
- Versión de Trivy:
- Fecha y hora de los análisis:

## Hallazgo seleccionado

| Campo | Antes | Después |
|---|---|---|
| Componente | | |
| Versión resuelta | | |
| CVE seleccionado | | |
| Severidad reportada | | |
| Presencia del hallazgo | | |
| Estado del quality gate | | |

## Análisis

1. ¿La dependencia era directa o transitiva?
2. ¿Qué cambio se realizó y por qué?
3. ¿Qué pruebas se ejecutaron para verificar compatibilidad?
4. ¿Qué evidencia muestra que desapareció el hallazgo seleccionado?
5. ¿Qué otros hallazgos o limitaciones quedan pendientes?
```

Entregar:

- Enlace al repositorio y al PR.
- Workflow SCA y configuración de Dependabot.
- SBOM y reporte de ambas ejecuciones, identificados por commit.
- Comparación completada y capturas de los pasos relevantes.

Los artifacts expiran a los siete días con esta configuración: descargar las evidencias necesarias para la entrega. Los resultados pueden cambiar si se actualiza la base de vulnerabilidades, incluso cuando el código permanece igual.

### Lista de comprobación

- [ ] El proyecto compila y ejecuta sus pruebas.
- [ ] El SBOM refleja las versiones resueltas actuales.
- [ ] Se identifica el hallazgo objetivo en la ejecución inicial.
- [ ] El gate bloquea HIGH/CRITICAL y publica las evidencias disponibles.
- [ ] Dependabot tiene configuración para Maven y Actions.
- [ ] Se verifica el efecto de una actualización o eliminación de dependencia.
- [ ] Los hallazgos pendientes quedan documentados.

## 14. Extensión opcional — Comparar con Snyk

Realizar esta sección solo si el grupo dispone de cuenta, permisos y capacidad de análisis en Snyk. El flujo principal no necesita un token externo.

1. Obtener el token de Snyk según las opciones disponibles para la cuenta.
2. En GitHub, abrir **Settings → Secrets and variables → Actions**.
3. Crear el secreto `SNYK_TOKEN`. Nunca escribirlo en el YAML o en el repositorio.
4. Instalar la CLI de Snyk en un job con Java/Maven y Node.js disponibles.
5. Ejecutar `snyk test --file=pom.xml --severity-threshold=high` con `SNYK_TOKEN` en el entorno del paso.
6. Comparar alcance, identificadores, severidad y recomendaciones con Trivy.

Ejemplo de pasos para añadir a un **job separado**, después de checkout y de configurar Java y Maven:

```yaml
      - name: Configurar Node.js para Snyk
        uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Instalar Snyk CLI
        run: npm install --global snyk

      - name: Analizar dependencias con Snyk
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        run: snyk test --file=pom.xml --severity-threshold=high
```

Para reproducibilidad, fijar una versión comprobada de la CLI en lugar de instalar la versión disponible en cada ejecución. Los secretos normalmente no se entregan a PRs procedentes de forks ni a los workflows de PRs de Dependabot; esta extensión necesita un diseño explícito de eventos y secretos para esos casos. No usar `pull_request_target` para ejecutar código no confiable con el token. Durante la clase, ejecutarla sobre una rama propia de confianza.

Si ambos escáneres discrepan, revisar cobertura, versiones resueltas, fuentes de avisos y fecha de análisis; no asumir que uno es correcto solo porque reporta más hallazgos.

## 15. Problemas frecuentes

| Problema | Qué revisar |
|---|---|
| `bom.json` no existe | Raíz correcta, resolución de Maven, comando CycloneDX y carpeta `target`. |
| SBOM muestra una versión inesperada | `dependency:tree`, parent/BOM, perfiles y mediación de versiones de Maven. |
| Docker no encuentra el SBOM | Ruta montada, terminal utilizada y existencia de `target/bom.json`. |
| Imagen o base no se descarga | Acceso al registro, DNS, proxy, límites del proveedor; revisar logs antes de reintentar. |
| Actions falla antes de SCA | Compilación, Java y servicios requeridos por las pruebas. |
| Gate sigue rojo tras corregir Commons Text | Otros hallazgos HIGH/CRITICAL o nueva versión todavía vulnerable. |
| No aparece un PR de Dependabot | YAML en rama predeterminada, configuración de seguridad, logs y actualización resoluble. |
| Artifact no contiene todos los archivos | El proceso pudo fallar antes de generarlos; `always()` no crea archivos inexistentes. |
| Snyk informa falta de autenticación | Secreto, evento del workflow, acceso al token y restricciones de la cuenta. |

## 16. Cierre de la práctica

Cada grupo explica en un minuto qué dependencia revisó, qué cambió y qué evidencia demuestra el resultado. Conservar los workflows de SCA y Semgrep: analizan superficies diferentes. Para terminar, retirar del laboratorio la dependencia de ejemplo si no es necesaria y comprobar nuevamente el pipeline.

## 17. Documentación oficial

Referencias consultadas el 30 de septiembre de 2026:

- [CycloneDX Maven Plugin](https://cyclonedx.github.io/cyclonedx-maven-plugin/).
- [Versiones publicadas de CycloneDX Maven Plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin/releases).
- [Trivy: análisis de SBOM](https://trivy.dev/docs/latest/guide/target/sbom/).
- [Trivy: historial de versiones](https://github.com/aquasecurity/trivy/blob/main/CHANGELOG.md).
- [Apache Commons Text: aviso de CVE-2022-42889](https://commons.apache.org/proper/commons-text/security.html).
- [GitHub: configurar actualizaciones de versiones de Dependabot](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-version-updates).
- [GitHub: configurar actualizaciones de seguridad](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-security-updates).
- [GitHub: artifacts de workflows](https://docs.github.com/en/actions/tutorials/store-and-share-data).
- [Snyk: autenticación de la CLI](https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli).
- [Snyk: integración con GitHub Actions](https://github.com/snyk/actions).

**Alcance de validación:** comandos y opciones preparados con documentación oficial; el workflow debe probarse en el repositorio real del curso. No se ha ejecutado aquí contra ese proyecto ni se conocen su POM actual, su versión de Java o sus servicios de pruebas.
