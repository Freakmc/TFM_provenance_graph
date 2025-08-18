#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Script: capture.sh
# Descripción: Captura eventos crudos del sistema auditd desde hace N horas.
#
# Uso:
#   sudo ./capture.sh [duración_en_horas]
#
# Ejemplos:
#   sudo ./capture.sh         # Captura las últimas 24 horas (valor por defecto)
#   sudo ./capture.sh 12      # Captura las últimas 12 horas
#
# Salida:
#   Crea el archivo logs_auditd_raw.txt en el mismo directorio
# -----------------------------------------------------------------------------

# Duración (en horas), por defecto 24 si no se indica
HOURS_AGO=${1:-24}
OUT="logs_auditd_raw.txt"

echo "[*] Extrayendo logs de las últimas $HOURS_AGO horas..."

# Extrae eventos desde hace N horas hasta ahora en formato raw
ausearch --raw --input-logs -ts now-${HOURS_AGO}h -te now > "$OUT"

# Cambia la propiedad del archivo al usuario real que ejecutó sudo
chown $(logname) "$OUT"

echo "[✓] Log guardado en $OUT"

#Antes de ejecutar dar permiso de ejcución al ejecutable con
#chmod +x capture.sh
