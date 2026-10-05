# Comparación del análisis SCA

> Basada en la plantilla del documento de apoyo 02 (sección 13). Los datos salen de las ejecuciones
> reales de GitHub Actions de este repositorio; los campos entre `<...>` los completa el estudiante.

## Identificación

- Grupo / estudiante: `<completar>`
- Repositorio: https://github.com/copipaste/spring-boot-webapi-secure
- Commit anterior (app vulnerable, gate en rojo): `f3cb635` (rama `feature/pipelines-fix`)
- Commit posterior (app remediada, gate en verde): `0cbfad3` (rama `feature/remediation`)
- Ejecución anterior: https://github.com/copipaste/spring-boot-webapi-secure/actions/runs/37240139116
- Ejecución posterior: https://github.com/copipaste/spring-boot-webapi-secure/actions/runs/37240328073 (mismo árbol de archivos que `0cbfad3`; ver también la ejecución de `0cbfad3` en la pestaña Actions)
- Pull request: `<URL del PR de remediación>`
- Versión de Trivy: 0.74.0 (`aquasec/trivy:0.74.0`) sobre el SBOM CycloneDX 1.6 generado con `cyclonedx-maven-plugin` 2.9.3
- Fecha y hora de los análisis: 2026-10-04 (los resultados pueden cambiar si se actualiza la base de vulnerabilidades, incluso con el mismo código)

## Hallazgo seleccionado

| Campo | Antes | Después |
|---|---|---|
| Componente | `org.apache.commons:commons-text` | `org.apache.commons:commons-text` |
| Versión resuelta | 1.9 | 1.15.0 |
| CVE seleccionado | CVE-2022-42889 (Text4Shell) | no aparece |
| Severidad reportada | CRITICAL | — |
| Presencia del hallazgo | Sí | No |
| Estado del quality gate | RECHAZADO | APROBADO |

## Evolución del conteo HIGH/CRITICAL de Trivy sobre el SBOM

| Paso | Cambio | HIGH + CRITICAL |
|---|---|---|
| Antes | Spring Boot 3.5.14, `commons-text` 1.9 | **23** (incluye `commons-text` y varios CVE CRITICAL de `tomcat-embed-core` 10.1.54) |
| 1 | `commons-text` 1.15.0 y Spring Boot 3.5.16 (Tomcat 10.1.55) | **8**: 3 CRITICAL en `tomcat-embed-core` 10.1.55 (CVE-2026-65182, -65905, -68525; corregidos en 10.1.58) y 5 HIGH en `jackson-core`/`jackson-databind` 2.21.4 (corregidos en 2.21.7) |
| 2 | `tomcat.version` = 10.1.60 y `jackson-bom.version` = 2.21.7 | **0** (quedan 2 MEDIUM, listados en el reporte sin bloquear) |

## Segundo escáner: Dependency-Check (nightly)

Trivy y Dependency-Check usan bases y fuentes distintas, así que sus resultados difieren (lo anticipa el documento de apoyo 02).

| Paso | Dependency-Check | Quality Gate |
|---|---|---|
| Rama vulnerable, ejecución **local** | 83 vulnerabilidades: 20 CRITICAL, 26 HIGH, 35 MEDIUM, 2 LOW (incluye `commons-text` 1.9, CVE-2022-42889) | RECHAZADO |
| `main` remediada, [nightly 37246425913](https://github.com/copipaste/spring-boot-webapi-secure/actions/runs/37246425913) | **15** HIGH/CRITICAL en Spring Framework 6.2.19 y Spring Security 6.5.11 (Trivy sobre el SBOM: 0) | RECHAZADO |
| `main` + riesgo aceptado con caducidad | 0 HIGH/CRITICAL activos, 10 MEDIUM, 1 LOW; **15 suprimidos** hasta 2026-12-31 | APROBADO |

Esos 15 CVE no tienen corrección de código abierto en las líneas 6.x (`6.2.20` y `6.5.12` son solo para clientes con soporte comercial; las versiones abiertas
son Spring Framework 7.0.9 y Spring Security 7.0.7/7.1.1, es decir, Spring Boot 4.x) y afectan a funciones que la aplicación no usa.
El análisis por CVE está en [`riesgos-aceptados.md`](riesgos-aceptados.md); la supresión es explícita, acotada a esas dos versiones y **caduca el 2026-12-31**.

## Análisis

1. **¿La dependencia era directa o transitiva?** `commons-text` es **directa** (declarada en `pom.xml`). `tomcat-embed-core` y `jackson-*` son **transitivas**: las incorporan `spring-boot-starter-web` y su versión la administra el BOM de Spring Boot.
2. **¿Qué cambio se realizó y por qué?** `commons-text` 1.9 → 1.15.0 (la 1.10.0 es el mínimo histórico que corrige CVE-2022-42889; se tomó la última estable). Para las transitivas se siguió la recomendación del doc 02 (sección 12): primero se actualizó el parent (3.5.14 → 3.5.16) y, como el BOM aún traía versiones afectadas, se sobrescribieron `tomcat.version` y `jackson-bom.version` con parches de la misma línea (10.1.x y 2.21.x).
3. **¿Qué pruebas se ejecutaron para verificar compatibilidad?** `mvn clean verify` en CI (JUnit + JaCoCo, incluidas pruebas nuevas de inyección SQL, escape de HTML y control de acceso) y la prueba de humo de la imagen Docker (el contenedor debe llegar a *healthy*). `commons-text` no se usa en el código, así que ese cambio no tiene riesgo funcional.
4. **¿Qué evidencia muestra que desapareció el hallazgo seleccionado?** El reporte `sca-report.json` (artefacto `sca-sbom`) y la tabla del *Job Summary* / anotación "Quality Gate - resumen": antes listaba `CVE-2022-42889`, después no.
5. **¿Qué otros hallazgos o limitaciones quedan pendientes?** Dos hallazgos MEDIUM del SBOM (no bloquean según la política HIGH/CRITICAL). Las sobrescrituras de `tomcat.version` y `jackson-bom.version` deben revisarse y retirarse cuando Spring Boot actualice su BOM. Limitaciones: un hallazgo por versión no demuestra que un endpoint sea explotable; el SBOM solo cubre dependencias de compilación/ejecución (no las de prueba) ni el sistema operativo de la imagen (eso lo cubre el escaneo de la imagen con Trivy en el CD); Dependency-Check (nightly) puede aportar hallazgos distintos a Trivy porque usa otra base de datos.
