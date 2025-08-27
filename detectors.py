# ──────────────────────────────────────────────────────────────────────────────
# Imports
# ──────────────────────────────────────────────────────────────────────────────
import csv                  # lectura de CSV con DictReader
import hashlib              # cálculo de hash SHA256 de ficheros
import ipaddress            # utilidades para clasificar IPs (privadas/local/etc.)
from pathlib import Path    # rutas de ficheros multiplataforma

# ──────────────────────────────────────────────────────────────────────────────
# Constantes y listas de control (tuning de reglas)
# ──────────────────────────────────────────────────────────────────────────────

# padres/procesos “permitidos” para root (ruido del sistema)
ROOT_ALLOW_PARENTS = {
    "systemd", "systemd-executor", "init", "cron", "anacron",
    "snapd", "apt", "apt-get", "dpkg", "NetworkManager", "sshd",
    "nscd", "rsyslogd", "journald", "systemd-udevd",
}
# Binaries habitualmente usados en ataques o living-off-the-land
SUSPECT_BIN_NAMES = {"nc", "ncat", "socat", "telnet", "wget", "curl", "python", "python3", "perl", "bash", "sh"}
# Directorios inusuales para colocar binarios ejecutables
UNUSUAL_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/run", "/home")  
# Directorios considerados seguros para ejecutables legítimos del sistema
SAFE_EXEC_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/snap/")

# ──────────────────────────────────────────────────────────────────────────────
# Carga de IOCs (hashes e IPs) desde CSV
# ──────────────────────────────────────────────────────────────────────────────
def load_iocs(csv_path):
    """
    Carga indicadores de compromiso (IOCs) desde un archivo CSV. El CSV debe tener columnas 'hash' (SHA256) e 'ip'.
    Devuelve dos sets: uno con hashes, otro con IPs.
    """
    hashes, ips = set(), set()
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):   # Normalizamos: hash en minúsculas, ip con espacios recortados
            h = (row.get("hash") or "").strip().lower()
            ip = (row.get("ip") or "").strip()
            if h: hashes.add(h)
            if ip: ips.add(ip)
    return hashes, ips

# ──────────────────────────────────────────────────────────────────────────────
# Utilidades auxiliares
# ──────────────────────────────────────────────────────────────────────────────
def file_sha256(path: str):
    """Devuelve el SHA256 del fichero si existe y es accesible; si no, None.
    Lee en chunks (1 MB) para no cargar archivos grandes en memoria.
    """
    try:
        p = Path(path)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None # Cualquier error (permisos/ENOENT/etc.) → se ignora devolviendo None

def is_private_or_local(ip: str) -> bool:
    """True si la IP es privada/loopback/link-local/reservada/multicast.
    Si no se puede parsear la IP, devolvemos True (conservador: no alertar).
    """
    try:
        ipobj = ipaddress.ip_address(ip)
        return (
            ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local
            or ipobj.is_reserved or ipobj.is_multicast
        )
    except Exception:
        return True  # si no sabemos parsear, lo tratamos como no interesante

def _parent_comm(u, G):
    """Devuelve el 'exe/comm' del padre de un proceso (hasta 2 saltos hacia atrás).
    Buscamos aristas entrantes hacia 'u' y devolvemos el 'exe' del nodo proc padre.
    """
    # Nota: en la práctica se revisa el primer predecessor 'process:*' alcanzable
    for pred, _, d in G.in_edges(u, data=True):
        if str(pred).startswith("proc:"):
            return G.nodes[pred].get("exe") or G.nodes[pred].get("comm")
    return None

# ──────────────────────────────────────────────────────────────────────────────
# Detector principal: examina cada arista (evento) y devuelve etiquetas de alerta
# ──────────────────────────────────────────────────────────────────────────────
def check_event(u, v, d, G, ioc_hashes, ioc_ips):
    """Analiza un evento (arista u→v con datos 'd') y devuelve lista de 'tags'.
    - u, v: IDs de nodos en G (u = origen, v = destino)
    - d: dict con metadatos de arista (incluye 'etype')
    - G: grafo completo para consultar atributos (exe, uid, ip, etc.)
    - ioc_hashes/ioc_ips: sets cargados desde CSV
    """
    tags = set()
    et = d.get("etype")

    # ── Casuística para aristas EXEC (process → file):
    if et == "EXEC":
        # Ruta y nombre del ejecutable objetivo
        exe_path = G.nodes[v].get("path", "") if v.startswith("file:") else ""
        exe_name = Path(exe_path).name or v.split("file:")[-1]
        # 1) nombre sospechoso sólo si NO está en rutas seguras
        if exe_name in SUSPECT_BIN_NAMES and not exe_path.startswith(SAFE_EXEC_DIRS):
            tags.add("BIN_SUSPICIOUS")
        # 2) ejecutable en dir inusual
        if exe_path and exe_path.startswith(UNUSUAL_DIRS) and not exe_path.startswith(SAFE_EXEC_DIRS):
            tags.add("BIN_UNUSUAL_PATH")
        # 3) sin extensión sólo cuenta si además está en dir inusual
        if "." not in exe_name and exe_path.startswith(UNUSUAL_DIRS):
            tags.add("BIN_NOEXT_IN_UNUSUAL_DIR")
        # 4) hash real del binario (si accesible)
        h = file_sha256(exe_path) if exe_path else None
        if h and h in ioc_hashes:
            tags.add("IOC_HASH_MATCH")
        # 5) padre sospechoso (shell/interpretador) lanzando desde dir inusual
        parent = _parent_comm(u, G)
        if parent and any(p in parent for p in ("sh", "bash", "python", "perl")) \
           and exe_path.startswith(UNUSUAL_DIRS):
            tags.add("SUSPICIOUS_PARENT_CHAIN")

    # ── Casuística para aristas CONNECT (process → socket):
    elif et == "CONNECT":
        uid = G.nodes[u].get("uid")
        ip  = G.nodes[v].get("ip") if str(v).startswith("net:") else ""

        # 1) IP en lista de IOCs
        if ip in ioc_ips:
            tags.add("IOC_IP_MATCH")
        # 2) root conectando hacia IP externa y con padre NO permitido
        if uid == 0 and ip and not is_private_or_local(ip):
            parent = (_parent_comm(u, G) or "").lower()
            if not any(p in (parent or "") for p in (p.lower() for p in ROOT_ALLOW_PARENTS)):
                tags.add("ROOT_EXTERNAL_CONNECT")
        # 3) Proceso ejecutando desde /tmp (u otros dirs inusuales) conectando fuera
        exe = (G.nodes[u].get("exe") or "")
        if exe.startswith(UNUSUAL_DIRS) and ip and not is_private_or_local(ip):
            tags.add("TMP_OUTBOUND")
            
    # Devolvemos lista ordenada para estabilidad de salida
    return sorted(tags)
