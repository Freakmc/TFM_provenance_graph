"""check_columns.py
    Valida rápidamente que un log crudo de auditd contiene las columnas
    mínimas (Time, PID, UID) *después* de la normalización definida en
    provenance_corrected.py.  Uso:

        python check_columns.py logs_auditd_raw.txt

    Salida de ejemplo:
        [✓] Claves detectadas: ['process', 'network', 'filecreate', ...]
        [✓] process   -> columnas correctas
        [!] network   -> faltan {'UID'}
"""
from pathlib import Path
import sys
import re
from auditdpythonparser import parsedata
import pandas as pd

# --- Normalización idéntica a provenance_corrected.py --------------------
COLUMN_MAP = {
    r"^exe(path|name)?$": "ExeName",
    r"^command(line)?$": "CmdLine",
    r"^pid$": "PID",
    r"^ppid$": "PPID",
    r"^au?id$": "UID",
    r"^uid$": "UID",
    r"^(time|timestamp|epoch|datetime)$": "Time",
    r"^(dst|dest)?ip$": "DstIP",
    r"^(dst|dest)?port$": "DstPort",
    r"^address$": "DstIP",
    r"^port$": "DstPort",
    r"^file(path)?[0-9]?$": "FilePath",
    r"^commandline$": "CmdLine",
    r"^exe$": "ExeName",
}
REGEX_FLAGS = re.IGNORECASE
REQUIRED = {"Time", "PID", "UID"}
PATH = "logs_auditd_raw.txt"


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    for regex, std in COLUMN_MAP.items():
        matches = [c for c in df.columns if re.match(regex, c, REGEX_FLAGS)]
        if not matches:
            continue
        if std in df.columns:
            for m in matches:
                if m == std:
                    continue
                df[std] = df[std].combine_first(df[m])
                df.drop(columns=m, inplace=True)
        else:
            first, *rest = matches
            df.rename(columns={first: std}, inplace=True)
            for m in rest:
                df[std] = df[std].combine_first(df[m])
                df.drop(columns=m, inplace=True)
    return df.loc[:, ~df.columns.duplicated()]


# --- CLI -----------------------------------------------------------------

log_path = Path(PATH)
if not log_path.exists():
    sys.exit(f"Archivo no encontrado: {log_path}")

raw_txt = log_path.read_text(encoding="utf-8")

dfs = parsedata(raw_txt)
print("[OK] Claves detectadas:", list(dfs.keys()))

for name, df in dfs.items():
    df = normalize_columns(df)
    missing = REQUIRED - set(df.columns)
    if missing:
        print(f"[!] {name:<12} -> faltan {missing}")
    else:
        print(f"[OK] {name:<12} -> columnas correctas")


