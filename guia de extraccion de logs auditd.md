# Guía rápida: extracción de logs **auditd** para usar la herramienta de proveniencia

Esta guía te asegura un **lote de logs válido** para el parser (incluye eventos `EXECVE`, `CONNECT/SOCKADDR` y acceso a ficheros en `/tmp`). Está pensada para una demo en una VM Ubuntu y procesado posterior en Windows con Python 3.11.

---

## Requisitos previos

- Ubuntu (con `systemd`) con `auditd` instalado:

```bash
sudo apt-get update && sudo apt-get install -y auditd audispd-plugins gcc curl
```

- Usuario con permisos `sudo`.

---

## Paso 0 — Arrancar **auditd** limpio

```bash
# parar auditd
sudo systemctl stop auditd

# (opcional) respaldar/vaciar logs para arrancar de cero
sudo mkdir -p /var/log/audit/backups
sudo mv /var/log/audit/audit.log /var/log/audit/backups/audit.log.$(date +%F_%T) 2>/dev/null || true
sudo rm -f /var/log/audit/audit.log.* 2>/dev/null || true

# arrancar auditd y habilitar
sudo systemctl start auditd
sudo auditctl -D
sudo auditctl -e 1

# comprobar estado → debe decir `enabled 1`
sudo auditctl -s
```

---

## Paso 1 — Cargar reglas de la demo

> **Importante:** la *key* es `ejecucion` (sin **t**).

```bash
sudo auditctl -D
sudo auditctl -e 1

# procesos: execve
sudo auditctl -a always,exit -F arch=b64 -S execve   -k ejecucion

# red: connect
sudo auditctl -a always,exit -F arch=b64 -S connect  -k conexiones

# ficheros: /tmp (watch)
sudo auditctl -w /tmp -p war -k ficheros_tmp

# verificación
sudo auditctl -l
```

**Notas**

- Las reglas usan `arch=b64` → compila binarios a 64 bits o ejecuta binarios del sistema.
- Puedes hacer persistentes estas reglas en `/etc/audit/rules.d/99-demo.rules` (opcional), pero para una demo temporal basta con `auditctl`.

---

## Paso 2 — Generar actividad (payload de demo)

Cualquier acción que provoque `execve`, `connect` y accesos a `/tmp` vale. Ejemplo minimalista:

```bash
# 1) red inet (CONNECT + SOCKADDR con IP/puerto)
curl -s http://1.1.1.1 >/dev/null 2>&1 || true

# 2) ejecución de un binario (EXECVE)
/bin/true || true

# 3) actividad en /tmp (openat/creación)
mkdir -p /tmp/demo_auditd
bash -lc 'echo hello > /tmp/demo_auditd/p.txt'
```

> Si usas tu `evil.c`, compílalo en 64 bits y ejecútalo:
>
> ```bash
> gcc -m64 -O2 evil.c -o evil
> ./evil || true  # aunque falle la conexión, deja rastro en audit
> ```

---

## Paso 3 — **Extraer** los logs en crudo (formato que entiende el parser)

### Opción recomendada (con rotaciones):

```bash
sudo ausearch --raw --input-logs -ts today > logs_auditd_raw.txt
```

### Alternativas

- Sin filtro por tipos (simple):
  ```bash
  sudo ausearch --raw --input-logs -ts today > logs_auditd_raw.txt
  ```
- Por tipos relevantes (útil si el log es muy grande):
  ```bash
  sudo ausearch --raw --input-logs -ts today \
    -m SYSCALL -m EXECVE -m SOCKADDR -m CWD -m PATH -m PROCTITLE \
    > logs_auditd_raw.txt
  ```
- Copia directa de los ficheros de audit (aún más “crudo”):
  ```bash
  sudo sh -c 'cat /var/log/audit/audit.log*' > logs_auditd_raw.txt
  ```

**No usar** `-i` (traducción a texto) para generar el fichero: el parser espera campos crudos `msg=audit(...)`, `type=...`, etc.

**Evita** filtrar por `-k` durante la extracción (los filtros se combinan en **AND** y un typo en la *key* puede vaciarte el lote).

---

## Paso 4 — Verificación rápida del fichero

```bash
grep -c 'msg=audit('     logs_auditd_raw.txt       # > 0
grep -c 'syscall=42'     logs_auditd_raw.txt       # > 0 (connect)
grep -c 'type=SOCKADDR'  logs_auditd_raw.txt       # > 0
grep -c 'syscall=59'     logs_auditd_raw.txt       # > 0 (execve)
grep -c 'type=EXECVE'    logs_auditd_raw.txt       # > 0
```

> Si `syscall=42` y/o `type=SOCKADDR` son **0**, añade una acción de red (p. ej., `curl` o `ping`) y vuelve a extraer.

---

## Paso 5 — Trasladar el fichero y procesar

- Copia `logs_auditd_raw.txt` a tu máquina Windows (SCP/WinSCP/Shared Folder).
- Ejecuta tu programa en Python 3.11:

```powershell
# Windows PowerShell
python provenance_from_auditd.py  # (asegúrate de que lee logs_auditd_raw.txt)
```

---

## Buenas prácticas y *gotchas*

- **No uses **``** al extraer**; si insistes, asegúrate de que las *keys* existen y recuerda que `ausearch` aplica **AND** entre filtros.
- **Key correcta:** `ejecucion` (no `ejecution`).
- **AF\_UNIX**: si solo hay sockets locales (p. ej., `/run/systemd/journal/socket`), añade **al menos una conexión inet** (`curl`/`ping`) para que el parser construya bien el bloque de red.
- **Rotaciones**: usa `--input-logs` o copia `audit.log*` para no perder eventos si el servicio giró el log.
- **64 bits**: las reglas usan `arch=b64`; compila tus binarios de demo con `-m64`.

---

## Solución de problemas

### `KeyError: 'Time'` dentro de `_networkchain`

1. Verifica que el log contiene `syscall=42` **y** `type=SOCKADDR` (>0).
2. Repite la extracción **sin** `-k` y con `--input-logs`.
3. (Opcional) aplica el *monkey‑patch* defensivo en tu script para tolerar lotes sin columna `Time`.

### `ausearch: no events found`

- Asegúrate de que `auditctl -s` muestra `enabled 1`.
- Revisa la ventana temporal (`-ts/-te`), la zona horaria, y que realmente ejecutaste acciones entre medias.

### El fichero es enorme

- Usa la variante por tipos (`-m ...`) o acota el rango de tiempo (`-ts HH:MM -te HH:MM`).

---

## “Comandos de la demo” (copiar y pegar)

```bash
# 0) reset + enable
auth_needed=1
sudo systemctl stop auditd
sudo mkdir -p /var/log/audit/backups && sudo mv /var/log/audit/audit.log /var/log/audit/backups/audit.log.$(date +%F_%T) 2>/dev/null || true
sudo rm -f /var/log/audit/audit.log.* 2>/dev/null || true
sudo systemctl start auditd && sudo auditctl -D && sudo auditctl -e 1 && sudo auditctl -s

# 1) reglas
audit_rules='
-a always,exit -F arch=b64 -S execve   -k ejecucion
-a always,exit -F arch=b64 -S connect  -k conexiones
-w /tmp -p war -k ficheros_tmp
'
echo "$audit_rules" | while read -r line; do [ -n "$line" ] && sudo auditctl $line; done
sudo auditctl -l

# 2) actividad
action() {
  curl -s http://1.1.1.1 >/dev/null 2>&1 || true
  /bin/true || true
  bash -lc 'echo hello > /tmp/demo_auditd/p.txt'
}
action

# 3) extracción
sudo ausearch --raw --input-logs -ts today > logs_auditd_raw.txt

# 4) verificación
for p in 'msg=audit(' 'syscall=42' 'type=SOCKADDR' 'syscall=59' 'type=EXECVE'; do echo -n "$p: "; grep -c "$p" logs_auditd_raw.txt; done
```

---

Con estos pasos tendrás un `logs_auditd_raw.txt` que tu programa puede procesar de forma estable y reproducible para la demo.

