#!/bin/bash
# Configura una instancia Amazon Linux 2023 para recibir los despliegues del laboratorio.
# Se ejecuta UNA vez, como root, desde TU PC (la llave de despliegue es una llave aparte, solo para
# GitHub Actions; tu llave personal no se comparte con nadie):
#
#   scp -i <tu-llave.pem> deploy/remote-deploy.sh infra/ec2-bootstrap.sh ec2-user@<IP>:/tmp/
#   ssh -i <tu-llave.pem> ec2-user@<IP> \
#     "sudo DEPLOY_PUBKEY='<clave PUBLICA de despliegue>' ALLOWED_IMAGE_REPO='ghcr.io/<usuario>/<repo>' \
#      bash /tmp/ec2-bootstrap.sh /tmp/remote-deploy.sh"
#
# Es re-ejecutable (no duplica nada).
set -euo pipefail

: "${DEPLOY_PUBKEY:?Define DEPLOY_PUBKEY (clave publica de despliegue, 'ssh-ed25519 AAAA... comentario')}"
: "${ALLOWED_IMAGE_REPO:?Define ALLOWED_IMAGE_REPO (ej. ghcr.io/usuario/repo, en minusculas)}"
WRAPPER_SRC="${1:-/tmp/remote-deploy.sh}"
[ -r "$WRAPPER_SRC" ] || { echo "ERROR: no encuentro $WRAPPER_SRC" >&2; exit 1; }
case "$DEPLOY_PUBKEY" in ssh-ed25519\ *|ssh-rsa\ *) ;; *) echo "ERROR: DEPLOY_PUBKEY no parece una clave publica SSH" >&2; exit 1 ;; esac
[ "$ALLOWED_IMAGE_REPO" = "$(echo "$ALLOWED_IMAGE_REPO" | tr 'A-Z' 'a-z')" ] || { echo "ERROR: ALLOWED_IMAGE_REPO debe ir en minusculas" >&2; exit 1; }

echo ">> 1/5 Docker"
dnf install -y docker >/dev/null
systemctl enable --now docker

echo ">> 2/5 Usuario 'deploy' (sin contrasena) en el grupo docker"
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
usermod -aG docker deploy
passwd -l deploy >/dev/null 2>&1 || true

echo ">> 3/5 Script de despliegue + configuracion"
install -m 755 -o root -g root "$WRAPPER_SRC" /usr/local/bin/deploy-webapi
printf 'ALLOWED_IMAGE_REPO=%s\n' "$ALLOWED_IMAGE_REPO" > /etc/deploy-webapi.conf
chmod 644 /etc/deploy-webapi.conf

echo ">> 4/5 Llave de GitHub Actions: SOLO puede ejecutar deploy-webapi (command= + restrict)"
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
printf 'restrict,command="/usr/local/bin/deploy-webapi" %s\n' "$DEPLOY_PUBKEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

echo ">> 5/5 Endurecer sshd (solo llaves, sin root, solo ec2-user y deploy)"
cat > /etc/ssh/sshd_config.d/90-lab-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
AllowUsers ec2-user deploy
EOF
sshd -t
systemctl reload sshd

echo
echo "==================== Listo ===================="
docker --version
echo "Huella ED25519 del servidor (compara con la que ves al conectar):"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
echo "Usuario de despliegue: $(id deploy)"
