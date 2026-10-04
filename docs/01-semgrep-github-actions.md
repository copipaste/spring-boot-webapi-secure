# Laboratorio 1: Semgrep con GitHub Actions

## Propósito

Incorporar análisis estático de seguridad (SAST) al pipeline del proyecto
`springboot-devsecops-lab`. Semgrep revisará el código Java sin ejecutar la
aplicación y generará evidencias que podrán descargarse desde GitHub Actions.

En esta primera práctica, los hallazgos **no bloquearán el pipeline**. El objetivo
es conocer la herramienta, revisar los resultados y diferenciar vulnerabilidades
reales, reglas genéricas y posibles falsos positivos.

## Resultado esperado

Al finalizar el laboratorio se tendrá:

- un job de Semgrep ejecutándose en cada `push` y `pull request`;
- análisis con reglas públicas y reglas locales;
- resultados visibles en el log de GitHub Actions;
- reportes JSON y SARIF descargables;
- una primera corrección validada mediante un nuevo análisis.

## Requisitos

- Repositorio `springboot-devsecops-lab` publicado en GitHub.
- GitHub Actions habilitado.
- Archivo `.semgrep.yml` ubicado en la raíz del proyecto.
- No se requiere una cuenta de pago ni un token de Semgrep.

> **Importante:** la aplicación contiene vulnerabilidades intencionales. Debe
> utilizarse solamente con fines académicos y no debe desplegarse en Internet.

---

## 1. Revisar las reglas locales

El repositorio incluye el archivo `.semgrep.yml`. Este archivo contiene reglas
preparadas para detectar algunos problemas del laboratorio:

- construcción insegura de consultas SQL;
- contenido HTML construido con datos del usuario;
- datos sensibles escritos en logs;
- secretos incorporados en el código;
- autorización global mediante `permitAll`;
- protección CSRF deshabilitada.

Verificar que el archivo se encuentre en la raíz:

```text
springboot-devsecops-lab/
├── .github/
├── .semgrep.yml
├── pom.xml
└── src/
```

Las reglas locales garantizan que el laboratorio produzca hallazgos conocidos.
Las reglas públicas permiten encontrar problemas adicionales y comparar ambos
tipos de análisis.

---

## 2. Crear el workflow

Crear el directorio `.github/workflows` si todavía no existe.

Dentro de ese directorio crear el archivo:

```text
.github/workflows/security-semgrep.yml
```

Agregar el siguiente contenido:

```yaml
name: Security - Semgrep

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  semgrep:
    name: SAST con Semgrep
    runs-on: ubuntu-latest

    container:
      image: semgrep/semgrep

    steps:
      - name: Descargar repositorio
        uses: actions/checkout@v6

      - name: Ejecutar Semgrep
        run: |
          semgrep scan \
            --config auto \
            --config .semgrep.yml \
            --metrics=off \
            --json-output=semgrep-results.json \
            --sarif-output=semgrep-results.sarif \
            src/main/java

      - name: Publicar reportes de Semgrep
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-reports
          path: |
            semgrep-results.json
            semgrep-results.sarif
          if-no-files-found: warn
          retention-days: 14
```

### ¿Qué realiza este workflow?

| Sección | Función |
|---|---|
| `push` | Ejecuta el análisis al enviar cambios a `main` o `develop` |
| `pull_request` | Analiza cambios antes de fusionarlos |
| `workflow_dispatch` | Permite ejecutar el análisis manualmente |
| `permissions` | Otorga solamente permiso de lectura al job |
| `container` | Ejecuta una imagen que ya contiene Semgrep |
| `--config auto` | Selecciona reglas públicas según los lenguajes encontrados |
| `--config .semgrep.yml` | Añade las reglas específicas del laboratorio |
| `--metrics=off` | Desactiva el envío de métricas en esta práctica |
| `--json-output` | Genera un reporte procesable por otras herramientas |
| `--sarif-output` | Genera un reporte compatible con plataformas de seguridad |
| `if: always()` | Conserva las evidencias aunque un paso anterior falle |

No se utiliza `SEMGREP_APP_TOKEN`, porque esta práctica trabaja con Semgrep
Community Edition y reglas disponibles sin suscripción.

---

## 3. Confirmar y enviar los cambios

Ejecutar:

```bash
git checkout -b feature/semgrep-sast
git add .semgrep.yml .github/workflows/security-semgrep.yml
git commit -m "security: add Semgrep SAST workflow"
git push -u origin feature/semgrep-sast
```

Crear un pull request desde `feature/semgrep-sast` hacia `main` o `develop`.

---

## 4. Observar la ejecución

En GitHub:

1. Abrir el repositorio.
2. Ingresar a **Actions**.
3. Seleccionar **Security - Semgrep**.
4. Abrir el job **SAST con Semgrep**.
5. Revisar el paso **Ejecutar Semgrep**.

Semgrep mostrará, entre otros datos:

- archivo y número de línea;
- identificador de la regla;
- severidad asignada;
- descripción del hallazgo;
- fragmento de código relacionado.

La ejecución inicial debería terminar correctamente aunque se encuentren
vulnerabilidades. Todavía no se agregó la opción `--error`.

---

## 5. Descargar las evidencias

En la parte inferior de la ejecución aparecerá el artefacto:

```text
semgrep-reports
```

Descargarlo y verificar que contenga:

```text
semgrep-results.json
semgrep-results.sarif
```

El archivo JSON puede utilizarse para automatización o consolidación de
resultados. SARIF es un formato estándar para intercambiar resultados de
herramientas de análisis estático.

---

## 6. Analizar los hallazgos

Completar una tabla como la siguiente:

| Regla | Archivo | Hallazgo | ¿Es real? | Prioridad | Corrección propuesta |
|---|---|---|---|---|---|
| `lab-java-sql-concatenation` | `ProductController.java` | Consulta construida con entrada externa | Sí | Alta | Consulta parametrizada |
|  |  |  |  |  |  |
|  |  |  |  |  |  |

Para cada hallazgo responder:

1. ¿Qué parte del código originó la alerta?
2. ¿Qué categoría OWASP puede relacionarse con el problema?
3. ¿La alerta representa una vulnerabilidad real o un falso positivo?
4. ¿Qué cambio permitiría corregirla?
5. ¿La corrección puede afectar el comportamiento funcional?

> Semgrep identifica patrones potencialmente inseguros. Un hallazgo no debe
> aceptarse ni descartarse automáticamente: necesita revisión y contexto.

---

## 7. Realizar una primera corrección

Modificar la búsqueda de productos para utilizar parámetros SQL.

Código vulnerable:

```java
String sql = "SELECT id, name, price FROM products WHERE name LIKE '%"
        + name + "%'";
return jdbcTemplate.queryForList(sql);
```

Código corregido:

```java
String sql = "SELECT id, name, price FROM products WHERE name LIKE ?";
return jdbcTemplate.queryForList(sql, "%" + name + "%");
```

Confirmar y enviar la corrección:

```bash
git add src/main/java
git commit -m "security: parameterize product search query"
git push
```

Revisar la nueva ejecución y comprobar que el hallazgo específico desaparece,
sin perder los demás hallazgos intencionales.

---

## 8. Activar el Quality Gate

Este paso se realiza después de analizar los resultados. Agregar `--error` al
comando de Semgrep:

```yaml
- name: Ejecutar Semgrep con Quality Gate
  run: |
    semgrep scan \
      --config auto \
      --config .semgrep.yml \
      --metrics=off \
      --error \
      --json-output=semgrep-results.json \
      --sarif-output=semgrep-results.sarif \
      src/main/java
```

Con `--error`, Semgrep devuelve un código de salida diferente de cero cuando
encuentra resultados que incumplen la política. El job será marcado como
fallido, pero el paso `if: always()` continuará publicando los reportes.

Para esta primera clase se recomienda:

1. ejecutar inicialmente sin `--error`;
2. revisar y clasificar los hallazgos;
3. corregir al menos una vulnerabilidad;
4. activar el gate al final para observar el cambio de comportamiento.

---

## 9. Visualización opcional en la pestaña Security

GitHub puede presentar archivos SARIF como alertas de *code scanning*. Esta
funcionalidad está disponible en repositorios públicos y en repositorios de
organización que tengan GitHub Code Security habilitado.

Si el repositorio cumple estas condiciones, cambiar los permisos:

```yaml
permissions:
  contents: read
  security-events: write
```

Después del paso que ejecuta Semgrep, agregar:

```yaml
- name: Publicar SARIF en GitHub Security
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: semgrep-results.sarif
    category: semgrep
```

Luego consultar:

```text
Security → Code scanning → Tool: Semgrep
```

Si el repositorio privado no tiene GitHub Code Security, omitir este paso. El
reporte seguirá disponible como artefacto sin necesidad de una suscripción.

---

## Evidencias a entregar

1. Captura del workflow ejecutado.
2. Captura de al menos tres hallazgos.
3. Tabla de análisis completada.
4. Enlace al pull request.
5. Evidencia del resultado antes y después de la corrección.
6. Breve conclusión de cinco a ocho líneas.

## Preguntas de reflexión

1. ¿Por qué las pruebas funcionales pueden pasar aunque existan vulnerabilidades?
2. ¿Qué ventaja ofrece ejecutar Semgrep en un pull request?
3. ¿Qué riesgo existe al bloquear el pipeline por cualquier alerta?
4. ¿Qué diferencia existe entre una regla pública y una regla propia?
5. ¿Qué criterio utilizaría para convertir un hallazgo en un Quality Gate?

## Problemas frecuentes

### El workflow no se ejecuta

- Verificar que el archivo termine en `.yml`.
- Verificar que esté en `.github/workflows/`.
- Confirmar que la rama utilizada sea `main` o `develop`.
- Ejecutarlo manualmente mediante **Run workflow**.

### No se encuentra `.semgrep.yml`

El archivo debe estar en la raíz del repositorio. Comprobar también que no haya
sido excluido accidentalmente por `.gitignore`.

### Los reportes no aparecen

- Confirmar los nombres `semgrep-results.json` y `semgrep-results.sarif`.
- Mantener `if: always()` en el paso de publicación.
- Revisar el mensaje del paso **Publicar reportes de Semgrep**.

### La publicación SARIF devuelve 403

El repositorio probablemente no tiene habilitado GitHub Code Security o el
workflow no posee `security-events: write`. En esta práctica puede retirarse el
paso de publicación SARIF y conservar solamente el artefacto descargable.

## Referencias

- [Semgrep: configuraciones CI oficiales](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs)
- [Semgrep: escritura de reglas](https://semgrep.dev/docs/writing-rules/overview)
- [GitHub: cargar resultados SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
