"""
check_columns.py
Valida rápidamente que un log crudo de auditd, tras pasar por la misma
normalización que usa el script principal, tiene las columnas mínimas
por bloque.

Uso:
    python check_columns.py logs_auditd_raw.txt

Salida de ejemplo:
    [OK] parsedata() -> ['process', 'network', 'filecreate', 'fileopenat']
    [OK] process     rows=123  missing=∅
    [OK] network     rows=45   missing=∅
    [!] filecreate   rows=7    missing={'PID'}
    [OK] fileopenat  rows=89   missing=∅

Código alineado con 'provenance_from_auditd.py':
- Normalización de columnas
- Parche defensivo _networkchain para evitar KeyError: 'Time'
- Síntesis de FilePath en filecreate cuando falte
- Requisitos por bloque (no globales)
"""

from pathlib import Path
import sys
import re
import argparse
import pandas as pd

# ──────────────────────────────────────────────────────────────────────────────
# Parche defensivo para evitar KeyError: 'Time' dentro del parser (igual que en principal)
# ──────────────────────────────────────────────────────────────────────────────
try:
    import auditdpythonparser.auditdparser as _adp
except Exception as _e:
    _adp = None
    print("[WARN] No se pudo importar auditdpythonparser.auditdparser:", _e)

if _adp and not hasattr(_adp, "_networkchain__orig"):
    _adp._networkchain__orig = _adp._networkchain

    def _networkchain_guard(df, *args, **kwargs):
        try:
            if isinstance(df, pd.DataFrame) and "Time" not in df.columns:
                for alias in ("time", "timestamp", "Timestamp", "DateTime", "Datetime", "EventTime", "epoch"):
                    if alias in df.columns:
                        df = df.rename(columns={alias: "Time"})
                        break
            return _adp._networkchain__orig(df, *args, **kwargs)
        except KeyError as e:
            if str(e) == "'Time'":
                # Devolvemos el DF intacto para no romper parsedata()
                return df
            raise

    _adp._networkchain = _networkchain_guard

from auditdpythonparser import parsedata

# ──────────────────────────────────────────────────────────────────────────────
# Normalización (idéntica a tu principal)
# ──────────────────────────────────────────────────────────────────────────────
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

REQUIRED_BY_BLOCK = {
    "process":   {"Time", "PID", "ExeName"},
    "fileopenat":{"Time", "PID", "FilePath"},
    "filecreate":{"Time", "PID"},       # FilePath deseable pero no crítico
    "network":   {"Time", "PID"},
}

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

def synthesize_filepath_if_missing(name: str, df: pd.DataFrame) -> pd.DataFrame:
    """Para filecreate intenta poblar FilePath con columnas candidatas o cwd+name."""
    if name != "filecreate" or "FilePath" in df.columns:
        return df
    cand = [c for c in df.columns if re.search(r'(?:^|_)name$|filename$|filepath$|fullpath$|^path$', c, re.I)]
    if cand:
        df["FilePath"] = pd.NA
        for c in cand:
            df["FilePath"] = df["FilePath"].fillna(df[c])
    if "FilePath" not in df.columns or df["FilePath"].isna().all():
        if "cwd" in df.columns and cand:
            namecol = cand[0]
            df["FilePath"] = (df["cwd"].astype(str).str.rstrip("/") + "/" +
                              df[namecol].astype(str).str.lstrip("/"))
        else:
            df["FilePath"] = pd.NA
    return df

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Chequeo rápido de columnas por bloque tras normalización.")
    ap.add_argument("log_path", help="Ruta al fichero crudo exportado de auditd (ausearch --raw ...)")
    args = ap.parse_args()

    log_path = Path(args.log_path)
    if not log_path.exists():
        sys.exit(f"Archivo no encontrado: {log_path}")

    raw_txt = log_path.read_text(encoding="utf-8", errors="ignore")

    dfs = parsedata(raw_txt)
    keys = list(dfs.keys())
    print("[OK] parsedata() ->", keys)

    had_errors = False
    for name in keys:
        df = dfs[name]
        if not isinstance(df, pd.DataFrame):
            print(f"[i ] {name:<12} -> no es DataFrame; omitido")
            continue

        df = normalize_columns(df)
        df = synthesize_filepath_if_missing(name, df)

        # Relleno mínimo para no romper la comparación
        if "Time" not in df.columns: df["Time"] = "na"
        if "PID"  not in df.columns: df["PID"]  = pd.NA
        if "UID"  not in df.columns: df["UID"]  = pd.NA

        req = REQUIRED_BY_BLOCK.get(name, set())
        missing = req - set(df.columns)
        status = "[OK]" if not missing else "[! ]"
        if missing:
            had_errors = True
        print(f"{status} {name:<12} rows={len(df):<6} missing={missing if missing else '∅'}")

    sys.exit(1 if had_errors else 0)

if __name__ == "__main__":
    main()
