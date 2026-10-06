# Riesgos aceptados de SCA (Dependency-Check)

Registro auditable de las excepciones de `dependency-check-suppressions.xml`. Fecha del análisis: 2026-10-05.

## Contexto

El nightly con OWASP Dependency-Check rechazó el Quality Gate con **15 hallazgos HIGH/CRITICAL**
([ejecución 37246425913](https://github.com/copipaste/spring-boot-webapi-secure/actions/runs/37246425913)):
12 en `spring-core` 6.2.19 y 3 en `spring-security-core` 6.5.11, las versiones que trae Spring Boot 3.5.16
(la última 3.5.x publicada). Trivy sobre el SBOM **no** los reporta a esta fecha: usa otras fuentes y bases de datos
(el documento de apoyo 02 pide justo eso, revisar cobertura, fuentes de avisos y fecha de análisis cuando los escáneres discrepan).

Los 15 CVE son reales según la NVD (los rangos afectados incluyen estas versiones), pero:

1. **No existe corrección de código abierto para las líneas 6.x.** Según los avisos de Spring, las correcciones `6.2.20`
   (Framework) y `6.5.12` (Security) son **solo para clientes con soporte comercial**. Las únicas versiones abiertas
   corregidas son Spring Framework **7.0.9** y Spring Security **7.0.7 / 7.1.1** (Spring Boot 4.x).
2. **La aplicación no usa ninguna de las funciones afectadas.**

## Análisis por CVE

| CVE | Severidad (CVSS) | Componente | Función afectada (según el aviso de Spring) | ¿La usa esta app? |
|---|---|---|---|---|
| CVE-2026-47884 | CRITICAL 9.8 | spring-core 6.2.19 | `XsltView` en Spring MVC: SSRF/RCE con un mapeo `/**` que renderiza vistas | No: no hay vistas ni XSLT; solo `@RestController` |
| CVE-2026-47885 | HIGH 7.5 | spring-core 6.2.19 | WebFlux: `PartEventHttpMessageReader` sin límite `maxPartSize` | No: no hay WebFlux |
| CVE-2026-47886 | HIGH 7.5 | spring-core 6.2.19 | SpEL con **expresiones suministradas por el usuario**: DoS con el operador `^` | No: no evalúa SpEL de usuario; el único `@Value` usa un placeholder `${...}` |
| CVE-2026-47888 | HIGH 7.5 | spring-core 6.2.19 | RSocket: fuga de memoria con un frame SETUP malformado | No: no hay RSocket |
| CVE-2026-47889 | HIGH 7.5 | spring-core 6.2.19 | WebFlux sobre el adaptador Jetty 12: cookies sin `SameSite` | No: sin WebFlux, y el servidor es Tomcat |
| CVE-2026-47890 | CRITICAL 9.8 | spring-core 6.2.19 | MVC/WebFlux: corrupción del flujo con SSE y *view fragments* | No: sin SSE ni vistas |
| CVE-2026-47891 | CRITICAL 9.8 | spring-core 6.2.19 | WebFlux con el procesador XML Aalto: no respeta `maxInMemorySize` | No: sin WebFlux ni Aalto |
| CVE-2026-47892 | CRITICAL 9.8 | spring-core 6.2.19 | WebFlux con *functional endpoints* y `DispatcherServlet`: bypass de predicado de cabecera en pre-flight | No: sin endpoints funcionales |
| CVE-2026-47893 | HIGH 7.5 | spring-core 6.2.19 | WebFlux con WebSocket: cabeceras en el motivo de una excepción | No: sin WebFlux ni WebSocket |
| CVE-2026-59282 | HIGH 7.5 | spring-core 6.2.19 | Data binding que aplica **property paths enviados por el usuario** sobre un objeto: DoS | No: los controladores usan `@RequestParam String`, `@PathVariable Long` y `@RequestBody Map`; sin `@ModelAttribute` ni `DataBinder` |
| CVE-2026-59283 | CRITICAL 9.1 | spring-core 6.2.19 | SpEL con `SimpleEvaluationContext` y compilador SpEL activo: bypass de la protección | No: no evalúa SpEL |
| CVE-2026-59313 | CRITICAL 9.8 | spring-core 6.2.19 | Spring MVC *functional web framework* con SSE: corrupción del flujo | No: sin endpoints funcionales ni SSE |
| CVE-2026-41707 | HIGH 7.4 | spring-security-core 6.5.11 | `DPoPProofJwtDecoderFactory`: replay de pruebas DPoP al vaciar la caché de `jti` | No: autentica con HTTP Basic; sin OAuth2/DPoP |
| CVE-2026-47841 | HIGH 7.4 | spring-security-core 6.5.11 | Soporte WebAuthn con almacén de sesión HTTP distribuido: bypass de verificación de usuario | No: sin WebAuthn |
| CVE-2026-59270 | CRITICAL 9.1 | spring-security-core 6.5.11 | `UnboundIdContainer` (servidor LDAP embebido) registra una credencial administrativa y escucha en todas las interfaces | No: no hay LDAP ni UnboundID en el árbol de dependencias |

Avisos: `https://spring.io/security/cve-2026-<número>` (uno por CVE). Se leyeron por completo los de CVE-2026-47890,
-59313, -59282 (Framework) y -41707, -59270 (Security); el resto se publicó en la misma tanda.

## Cómo se verificó que la app no usa esas funciones

1. **Código:** búsqueda en `src/` de `SseEmitter`, `ServerSentEvent`, `XsltView`, `RouterFunction`, `WebFlux`/`Mono`/`Flux`,
   `RSocket`, `WebSocket`, `SpelExpressionParser`/`#{`, `DataBinder`/`@ModelAttribute`/`BeanWrapper`, `DPoP`/`WebAuthn`/`UnboundID`/`LDAP`:
   **0 coincidencias** en todos los casos.
2. **Dependencias:** `mvn dependency:tree` no contiene `webflux`, `reactor`, `rsocket`, `unboundid`, `ldap`, `webauthn` ni `oauth2`;
   de Spring solo hay `spring-webmvc` y `spring-security-{core,web,config}`.
3. **Superficie expuesta:** la app publica cuatro endpoints MVC anotados (`/api/products/search`, `/api/comments/preview`,
   `/api/auth/login`, `/api/admin/users/{id}`) y `/actuator/health`; en producción corre con el perfil `prod`.

## Decisión y condiciones

- **Decisión:** aceptar el riesgo de forma **temporal** y acotada: se suprimen solo estos 15 CVE y solo para
  `spring-core@6.2.19` y `spring-security-core@6.5.11` (si cambia la versión, la supresión deja de aplicar).
- **Caducidad:** `until="2026-12-31"`. Al vencer, la supresión se ignora y el Quality Gate del nightly vuelve a fallar.
- **No se baja el umbral del gate:** sigue bloqueando HIGH y CRITICAL; las excepciones quedan visibles en el reporte de
  Dependency-Check (sección *Suppressed Vulnerabilities*).
- **Controles compensatorios:** puertos 8080/8081 solo desde la IP del propietario, perfil `prod` sin consola H2 ni Actuator completo,
  contenedor sin privilegios, límite de memoria.
- **Solución de fondo:** migrar a Spring Boot 4.x (Spring Framework 7.0.9, Spring Security 7.1.1). Es un salto de versión mayor: el PR
  #12 de Dependabot lo propone y hay que adaptar dependencias de prueba y las sobrescrituras de versiones del `pom.xml` (Tomcat 11, Jackson 3).
  Cuando se haga, se elimina esta excepción.

## Mismo registro para Trivy (Laboratorio Final)

Al escanear la imagen del proyecto, Trivy también reporta `CVE-2026-47884` (CRITICAL) en `spring-webmvc 6.2.19` (corrección solo
en Spring Framework 7.0.9), que es uno de los 15 CVE de esta tabla. Para que el Quality Gate no bloquee por un riesgo ya
analizado, los mismos 15 CVE están en `.trivyignore.yaml`, con la misma caducidad (`expired_at: 2026-12-31`) y la misma justificación.
Se aplica al análisis de la imagen, al de SBOM y al escaneo del CD; solo oculta esos 15 identificadores.

Verificación (2026-10-06, imagen `webapi` construida con este repositorio, Trivy 0.74.0):

| Escaneo | Sin `.trivyignore.yaml` | Con `.trivyignore.yaml` |
|---|---|---|
| CRITICAL | 1 (`CVE-2026-47884`) | 0 |
| MEDIUM | 2 (`commons-lang3`, `log4j-api`; corregidos subiendo a 3.18.0 y 2.25.5) | 0 |
| UNKNOWN | 1 (`libpng` de la imagen base Alpine, con corrección en `1.6.59-r0`) | 1 (pendiente de revisar) |
