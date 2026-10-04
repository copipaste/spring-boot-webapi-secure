# Demostración: el Quality Gate bloquea el merge

Este PR existe solo como evidencia del laboratorio. La rama `main` todavía contiene la aplicación
vulnerable, así que el job **CI / Quality Gate** rechaza (Semgrep, CodeQL, SpotBugs y Trivy reportan
hallazgos HIGH/CRITICAL) y la regla `protect-main` impide el merge, incluso al administrador.

**No debe mergearse.** El PR de remediación (`feature/remediation`) es el que corrige los hallazgos y
deja el gate en verde.
