#!/usr/bin/env bash
set -euo pipefail
exec >>/var/log/netatlas-update.log 2>&1
echo "[$(date --iso-8601=seconds)] Iniciando atualização"
INSTALL_DIR=/opt/netatlas
git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" diff --quiet
git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" diff --cached --quiet
git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" fetch origin main
git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" merge --ff-only origin/main
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
install -m 0644 "$INSTALL_DIR/index.html" "$INSTALL_DIR/portal.js" "$INSTALL_DIR/workflows.js" "$INSTALL_DIR/static/"
install -d -m 0755 "$INSTALL_DIR/static/icons"
cp -a "$INSTALL_DIR/icons/." "$INSTALL_DIR/static/icons/"
chown -R netatlas:netatlas "$INSTALL_DIR"
systemctl restart netatlas
echo "[$(date --iso-8601=seconds)] Atualização concluída"
