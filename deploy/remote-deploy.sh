#!/bin/bash
# Se instala en el servidor como /usr/local/bin/deploy-webapi (lo hace infra/ec2-bootstrap.sh).
# Es el UNICO comando que puede ejecutar la llave SSH de GitHub Actions (authorized_keys con
# command="..."), asi que aunque esa llave se filtrara solo permitiria desplegar esta app.
#
# GitHub Actions envia como comando SSH tres valores separados por espacios:
#     <ghcr.io/usuario/repo@sha256:digest> <webapi-prod|webapi-staging> <8080|8081>
# y este script los valida estrictamente antes de tocar Docker.
set -euo pipefail

CONF=/etc/deploy-webapi.conf
[ -r "$CONF" ] || { echo "ERROR: falta $CONF (define ALLOWED_IMAGE_REPO)" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
: "${ALLOWED_IMAGE_REPO:?ALLOWED_IMAGE_REPO no definido en $CONF}"

read -r IMAGE CONTAINER APP_PORT EXTRA <<< "${SSH_ORIGINAL_COMMAND:-}"
if [ -z "${APP_PORT:-}" ] || [ -n "${EXTRA:-}" ]; then
  echo "ERROR: uso: <imagen@sha256:digest> <webapi-prod|webapi-staging> <8080|8081>" >&2
  exit 2
fi

# Solo la imagen de ESTE repositorio, siempre por digest (inmutable)
if [ "${IMAGE%@*}" != "$ALLOWED_IMAGE_REPO" ] || ! [[ "${IMAGE#*@}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "ERROR: imagen no permitida: $IMAGE" >&2
  exit 2
fi
# Solo los dos destinos del laboratorio, cada uno con su puerto
case "${CONTAINER}:${APP_PORT}" in
  webapi-prod:8080 | webapi-staging:8081) ;;
  *) echo "ERROR: contenedor/puerto no permitidos: ${CONTAINER}:${APP_PORT}" >&2; exit 2 ;;
esac

echo ">> Desplegando $IMAGE como $CONTAINER en el puerto $APP_PORT"
docker pull "$IMAGE"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# SPRING_PROFILES_ACTIVE=prod desactiva la consola H2 y limita Actuator (application-prod.properties)
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "${APP_PORT}:8080" \
  -e SPRING_PROFILES_ACTIVE=prod \
  "$IMAGE" >/dev/null

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
docker logs --tail 100 "$CONTAINER" >&2 || true
exit 1
