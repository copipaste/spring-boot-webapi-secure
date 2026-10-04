#!/bin/bash
# Se ejecuta EN LA INSTANCIA EC2 (lo envia el job "Deploy to EC2" por AWS Systems Manager, como root).
# Variables que recibe en la primera linea del comando: IMAGE, CONTAINER, APP_PORT.
set -euo pipefail

docker pull "$IMAGE"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# SPRING_PROFILES_ACTIVE=prod desactiva la consola H2 y limita Actuator (application-prod.properties)
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "${APP_PORT}:8080" \
  -e SPRING_PROFILES_ACTIVE=prod \
  "$IMAGE"

for i in $(seq 1 40); do
  if curl -fsS "http://localhost:${APP_PORT}/actuator/health"; then
    echo
    echo "OK: ${CONTAINER} responde en el intento ${i}"
    docker image prune -f >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 3
done

echo "ERROR: ${CONTAINER} no respondio a tiempo" >&2
docker logs --tail 100 "$CONTAINER" || true
exit 1
