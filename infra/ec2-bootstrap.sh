#!/bin/bash
# Configura una instancia EC2 (Ubuntu o Amazon Linux 2023) para recibir los despliegues del laboratorio.
# Se ejecuta UNA vez, como root (sudo), desde TU PC. La llave de despliegue es una llave aparte, solo para
# GitHub Actions; tu llave personal del servidor no se comparte con nadie.
#
#   scp -i <llave.pem> deploy/remote-deploy.sh infra/ec2-bootstrap.sh <admin>@<IP>:/tmp/
#   ssh -i <llave.pem> <admin>@<IP> \
#     "sudo bash /tmp/ec2-bootstrap.sh '<clave PUBLICA de despliegue>' 'ghcr.io/<usuario>/<repo>' /tmp/remote-deploy.sh"
#   (<admin> = ubuntu en Ubuntu, ec2-user en Amazon Linux)
#
# Es re-ejecutable (no duplica nada).
set -euo pipefail

DEPLOY_PUBKEY="${1:-${DEPLOY_PUBKEY:-}}"
ALLOWED_IMAGE_REPO="${2:-${ALLOWED_IMAGE_REPO:-}}"
WRAPPER_SRC="${3:-/tmp/remote-deploy.sh}"
ADMIN_USER="${SUDO_USER:-}"   # el usuario con el que entraste: se conserva en AllowUsers para no quedarte fuera

[ -n "$DEPLOY_PUBKEY" ] || { echo "ERROR: falta la clave PUBLICA de despliegue (arg 1)" >&2; exit 1; }
[ -n "$ALLOWED_IMAGE_REPO" ] || { echo "ERROR: falta ALLOWED_IMAGE_REPO (arg 2, ej. ghcr.io/usuario/repo)" >&2; exit 1; }
[ -r "$WRAPPER_SRC" ] || { echo "ERROR: no encuentro $WRAPPER_SRC (arg 3)" >&2; exit 1; }
[ -n "$ADMIN_USER" ] && [ "$ADMIN_USER" != "root" ] || { echo "ERROR: ejecuta el script con sudo desde un usuario normal (ubuntu / ec2-user)" >&2; exit 1; }
case "$DEPLOY_PUBKEY" in ssh-ed25519\ * | ssh-rsa\ *) ;; *) echo "ERROR: la clave de despliegue no parece una clave publica SSH" >&2; exit 1 ;; esac
[ "$ALLOWED_IMAGE_REPO" = "$(echo "$ALLOWED_IMAGE_REPO" | tr 'A-Z' 'a-z')" ] || { echo "ERROR: ALLOWED_IMAGE_REPO debe ir en minusculas" >&2; exit 1; }

echo ">> 1/6 Docker"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y docker.io curl >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker >/dev/null
else
  echo "ERROR: ni apt-get ni dnf: distribucion no soportada" >&2; exit 1
fi
systemctl enable --now docker

echo ">> 2/6 Swap de 2 GB (la instancia tiene poca RAM; evita que el kernel mate la JVM)"
if [ -z "$(swapon --show --noheadings)" ]; then
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo ">> 3/6 Usuario 'deploy' (sin contrasena) en el grupo docker"
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
usermod -aG docker deploy
passwd -l deploy >/dev/null 2>&1 || true

echo ">> 4/6 Script de despliegue y configuracion"
install -m 755 -o root -g root "$WRAPPER_SRC" /usr/local/bin/deploy-webapi
printf 'ALLOWED_IMAGE_REPO=%s\n' "$ALLOWED_IMAGE_REPO" > /etc/deploy-webapi.conf
chmod 644 /etc/deploy-webapi.conf

echo ">> 5/6 Llave de GitHub Actions: SOLO puede ejecutar deploy-webapi (command= + restrict)"
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
printf 'restrict,command="/usr/local/bin/deploy-webapi" %s\n' "$DEPLOY_PUBKEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

echo ">> 6/6 Endurecer sshd (solo llaves, sin root, solo ${ADMIN_USER} y deploy)"
cat > /etc/ssh/sshd_config.d/90-lab-hardening.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
AllowUsers ${ADMIN_USER} deploy
EOF
mkdir -p /run/sshd
sshd -t   # si la configuracion fuera invalida, el script se detiene aqui y NO recarga nada
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then SSH_SVC=ssh; else SSH_SVC=sshd; fi
systemctl reload "$SSH_SVC"

echo
echo "==================== Listo ===================="
docker --version
echo "Swap: $(swapon --show --noheadings | awk '{print $1" "$3}' | tr '\n' ' ')"
echo "Huella ED25519 del servidor: $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"
echo "Usuario de despliegue: $(id deploy)"
echo "Usuarios permitidos por sshd: ${ADMIN_USER} deploy"
