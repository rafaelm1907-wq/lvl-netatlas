#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo 'Execute como root.' >&2; exit 1; fi
read -r -p 'IP ou URL do NetBox (ex.: http://10.0.0.10): ' NETBOX_URL
read -r -s -p 'Token do NetBox com escrita: ' NETBOX_TOKEN; echo
read -r -p 'IP ou DNS do banco Zabbix: ' ZABBIX_DB_HOST
read -r -p 'Porta do banco Zabbix [3306]: ' ZABBIX_DB_PORT; ZABBIX_DB_PORT=${ZABBIX_DB_PORT:-3306}
read -r -p 'Banco Zabbix [zabbix]: ' ZABBIX_DB_NAME; ZABBIX_DB_NAME=${ZABBIX_DB_NAME:-zabbix}
read -r -p 'Usuário somente leitura do Zabbix: ' ZABBIX_DB_USER
read -r -s -p 'Senha do usuário Zabbix: ' ZABBIX_DB_PASSWORD; echo
read -r -s -p 'Senha inicial do Superadmin NetAtlas: ' NETATLAS_SUPERADMIN_PASSWORD; echo
read -r -p 'URL do servidor de licenças (vazio para configurar depois): ' LICENSE_SERVER_URL

command -v apt-get >/dev/null || { echo 'Este instalador atualmente suporta Ubuntu/Debian (apt).' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv postgresql postgresql-contrib postgis
INSTALL_DIR=/opt/netatlas
[[ -d "$INSTALL_DIR/.git" ]] && { echo "$INSTALL_DIR já contém uma instalação. Atualize-a pelo Git ou escolha outro servidor." >&2; exit 1; }
SOURCE_DIR=$(cd "$(dirname "$0")" && pwd)

install -d -m 0750 /etc/netatlas
DB_PASSWORD=$(openssl rand -hex 24)
runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='netatlas_app') THEN CREATE ROLE netatlas_app LOGIN PASSWORD '${DB_PASSWORD}'; END IF;
END \$\$;
CREATE DATABASE netatlas OWNER netatlas_app ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' TEMPLATE template0;
SQL
runuser -u postgres -- psql -d netatlas -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS postgis;'

install -d -m 0755 "$INSTALL_DIR"
cp -a "$SOURCE_DIR/." "$INSTALL_DIR/"
install -d -m 0755 "$INSTALL_DIR/static/icons"
install -m 0644 "$INSTALL_DIR/index.html" "$INSTALL_DIR/portal.js" "$INSTALL_DIR/workflows.js" "$INSTALL_DIR/static/"
cp -a "$INSTALL_DIR/icons/." "$INSTALL_DIR/static/icons/"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
id netatlas >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin netatlas
install -m 0600 /dev/null /etc/netatlas/netatlas.env
cat > /etc/netatlas/netatlas.env <<EOF
NETBOX_URL=${NETBOX_URL%/}
NETBOX_TOKEN=${NETBOX_TOKEN}
ZABBIX_DB_HOST=${ZABBIX_DB_HOST}
ZABBIX_DB_PORT=${ZABBIX_DB_PORT}
ZABBIX_DB_NAME=${ZABBIX_DB_NAME}
ZABBIX_DB_USER=${ZABBIX_DB_USER}
ZABBIX_DB_PASSWORD=${ZABBIX_DB_PASSWORD}
NETATLAS_DB_DSN=postgresql://netatlas_app:${DB_PASSWORD}@127.0.0.1/netatlas
NETATLAS_SUPERADMIN_PASSWORD=${NETATLAS_SUPERADMIN_PASSWORD}
LICENSE_SERVER_URL=${LICENSE_SERVER_URL%/}
LICENSE_PRODUCT=LVL - NetAtlas
EOF
install -m 0644 "$INSTALL_DIR/netatlas.service" /etc/systemd/system/netatlas.service
chown -R netatlas:netatlas "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable --now netatlas
echo 'NetAtlas instalado. Acesse http://IP_DO_SERVIDOR:20050'
