# ---- Build stage ----
# Imagen de Maven oficial: no depende de mvnw ni de descargar Maven en cada build.
FROM maven:3-eclipse-temurin-24 AS builder
WORKDIR /app

# Primero el pom (mejor cache de capas) y luego el codigo
COPY pom.xml .
COPY src src
RUN mvn -B -DskipTests package

# ---- Runtime stage ----
# JRE (no JDK): imagen mas pequena y menor superficie de ataque
FROM eclipse-temurin:21-jre-alpine

# Seguridad: ejecutar como usuario sin privilegios (Alpine usa addgroup/adduser, no groupadd/useradd)
RUN addgroup -S spring && adduser -S -G spring spring

WORKDIR /app

# Solo el jar ejecutable (el .jar.original no coincide con *.jar)
COPY --from=builder --chown=spring:spring /app/target/*.jar app.jar

USER spring:spring
EXPOSE 8080

# Alpine no trae curl; BusyBox incluye wget
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
