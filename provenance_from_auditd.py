# ──────────────────────────────────────────────────────────────────────────────
# Imports
# ──────────────────────────────────────────────────────────────────────────────
from pathlib import Path                        # filesystem paths (OS‑independent)
import networkx as nx                           # graph model (MultiDiGraph)
from pyvis.network import Network               # interactive HTML visualization
import pandas as pd                             # tabular data manipulation
from datetime import datetime as dt, timedelta  # timestamps & deltas
import re                                       # regex utilities

# ──────────────────────────────────────────────────────────────────────────────
# User‑tunable toggles & color palettes
# ──────────────────────────────────────────────────────────────────────────────
SHOW_USER_EDGES = False   # if True, add explicit RUNS edges (user→proc) in main graph
ONLY_ALERT_EDGES = False  # if True, hide edges without alert tags in visualization

# Node colors by entity type (used in visualization)
COLOR = {
    "process": "#4C8BF5",      # azul
    "file":    "#F55D4C",      # coral
    "socket":  "#23B5AF",      # turquesa
    "user":    "#FFC857",      # mostaza
    "other":   "#BBBBBB"       # gris de reserva
}
# Edge colors by action type (used in visualization)
EDGE_COLOR = {
    "EXEC":    "#999999",
    "READ":    "#BDBDBD",
    "WRITE":   "#BDBDBD",
    "CREATE":  "#BDBDBD",
    "PARENT":  "#CCCCCC",
    "CONNECT": "#3E7CB1",
    "RUNS":    "#C9A227",
}
ALERT_EDGE_COLOR = "#D0021B"  # red for edges carrying alert tags

# ──────────────────────────────────────────────────────────────────────────────
# 1) PRE‑FLIGHT (opcional) — imprime en consola señales de que hay red/execve
# ──────────────────────────────────────────────────────────────────────────────
def preflight_raw(text: str) -> dict:
    pats = {
        "EXECVE (type)": r"\btype=EXECVE\b",
        "execve (syscall=59)": r"\bsyscall=59\b",
        "CONNECT (syscall=42)": r"\bsyscall=42\b",
        "SOCKADDR (type)": r"\btype=SOCKADDR\b",
        "msg=audit(...)": r"\bmsg=audit\(",
        "openat (syscall=257)": r"\bsyscall=257\b",
        'key="ejecucion"': r'key="ejecucion"',
        'key="conexiones"': r'key="conexiones"',
        'key="ficheros_tmp"': r'key="ficheros_tmp"',
    }
    return {k: len(re.findall(v, text)) for k, v in pats.items()}

# ──────────────────────────────────────────────────────────────────────────────
# 2) Defensive patch for auditdpythonparser._networkchain (avoid KeyError: 'Time')
#    We monkey‑patch _networkchain to auto‑rename common time aliases to 'Time'.
#    If 'Time' is still unavailable, return input df to keep pipeline alive.
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
                return df
            raise
    _adp._networkchain = _networkchain_guard

# Ahora sí, importamos el parser
from auditdpythonparser import parsedata

# ──────────────────────────────────────────────────────────────────────────────
# 3) Column normalization helpers (map heterogeneous names to a standard set)
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

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Renombra columnas heterogéneas a la convención estándar y elimina duplicados conservando el primer valor no nulo."""
    # 1. renombrar según patrones
    for regex, std in COLUMN_MAP.items():
        matches = [c for c in df.columns if re.match(regex, c, REGEX_FLAGS)]
        if not matches:
            continue
        if std in df.columns:   # Si la columna estándar ya existe, fusionamos y eliminamos duplicados
            for m in matches:
                if m == std:
                    continue
                df[std] = df[std].combine_first(df[m])
                df.drop(columns=m, inplace=True)
        else:
            first, *rest = matches
            df.rename(columns={first: std}, inplace=True)
            for m in rest:  # renombramos la primera coincidencia y fusionamos las demás
                df[std] = df[std].combine_first(df[m])
                df.drop(columns=m, inplace=True)
    # 2. eliminar cualquier duplicado residual conservando la primera
    df = df.loc[:, ~df.columns.duplicated()]
    return df

# ──────────────────────────────────────────────────────────────────────────────
# 4) Graph helpers & utilities
# ──────────────────────────────────────────────────────────────────────────────
G = nx.MultiDiGraph() # global graph collecting nodes/edges for the session

def _clean(s):
    """Normalize stringish values: strip whitespace and quotes."""
    return str(s).strip().strip('"').strip("'")

def ensure(n, t, **attrs):
    """Ensure a node 'n' exists with type 't'; if new, set optional attrs."""
    if n not in G:
        G.add_node(n, ntype=t, **attrs)

def fix_time(df: pd.DataFrame):
    """Ensure a 'Time' column exists (rename common alternatives)."""
    if "Time" in df.columns: return df
    for alt in ("time", "timestamp", "epoch", "DateTime"):
        if alt in df.columns: return df.rename(columns={alt: "Time"})
    raise ValueError(f"Columna de tiempo no encontrada en columnas: {list(df.columns)}")

def backward_tracking(node_id: str, depth=None):
    """Return upstream nodes (ancestors). Optionally limit by shortest‑path depth."""
    nodes = nx.ancestors(G, node_id)
    if depth:
        nodes = nx.single_source_shortest_path_length(G.reverse(), node_id, cutoff=depth).keys()
    return nodes

def forward_tracking(node_id: str, depth=None):
    """Return downstream nodes (descendants). Optionally limit by shortest‑path depth."""
    nodes = nx.descendants(G, node_id)
    if depth:
        nodes = nx.single_source_shortest_path_length(G, node_id, cutoff=depth).keys()
    return nodes

def subgraph_time(start_ts: str, end_ts: str):
    """Slice a subgraph whose edges have timestamp 'ts' within [start, end]."""
    start = dt.fromisoformat(start_ts)
    end   = dt.fromisoformat(end_ts)
    edges_in_range = [
        (u,v,k) for u,v,k,d in G.edges(keys=True, data=True)
        if start <= dt.fromisoformat(d["ts"]) <= end
    ]
    nodes = {u for u,v,_ in edges_in_range} | {v for u,v,_ in edges_in_range}
    return G.subgraph(nodes).copy()

def bind_user(pid, uid_raw, ts=None):
    """Create/associate a user node to a process via RUNS (user→proc) if missing."""
    if pd.isna(uid_raw):
        return
    uid_raw = str(uid_raw).strip().strip('"').strip("'")
    user_id = uid_raw if not uid_raw.isdigit() else int(uid_raw)
    user_node  = f"user:{user_id}"
    proc_node  = f"proc:{pid}"
    ensure(user_node, "user")
    # check if a RUNS edge already exists to avoid duplicates
    exists = False
    edata = G.get_edge_data(user_node, proc_node, default={})
    for k, attr in edata.items():          # MultiDiGraph stores parallel edges keyed by int
        if attr.get("etype") == "RUNS":
            exists = True
            break
    if not exists:
        G.add_edge(user_node, proc_node, etype="RUNS", ts=str(ts) if ts else "na")

def _parse_ts_to_dt(ts):
    """Best‑effort parse of 'ts' attribute into datetime (None if not parseable)."""
    if not ts or ts == "na":
        return None
    s = str(ts)
    try:
        return dt.fromisoformat(s)                 # admite 'YYYY-MM-DD HH:MM:SS[.uuuuuu]'
    except ValueError:
        try:
            return dt.fromisoformat(s.replace(" ", "T", 1))  # 'YYYY-MM-DDTHH:MM:SS'
        except ValueError:
            return None

def collect_edge_times(graph: nx.Graph):
    """Gather all parseable edge timestamps as a sorted list of datetimes."""
    times = []
    for _, _, d in graph.edges(data=True):
        t = _parse_ts_to_dt(d.get("ts"))
        if t:
            times.append(t)
    return sorted(times)

def visualize_time_window(graph: nx.Graph, width_seconds: int = 60, out_file: str = "graph_window.html"):
    """Auto‑select a time window of width_seconds that has content and render it."""
    times = collect_edge_times(graph)
    if not times:
        print("[INFO] No hay timestamps 'ts' parseables en las aristas; no se genera ventana temporal.")
        return
    window = timedelta(seconds=width_seconds)
    step = max(1, len(times)//25)   # probamos hasta 25 pivotes repartidos a lo largo de la línea temporal
    chosen = None
    SG = None
    for idx in list(range(0, len(times), step)) + [len(times)-1]:
        start = times[idx]
        end = start + window
        SG = subgraph_time(start.isoformat(), end.isoformat())
        if SG.number_of_nodes() > 0:
            chosen = (start, end)
            break
    if not chosen:  # fallback: toda la duración si ninguna ventana de 60s tiene nodos (raro)
        start, end = times[0], times[-1]
        SG = subgraph_time(start.isoformat(), end.isoformat())
        chosen = (start, end)
    print(f"[TIME] Ventana seleccionada: {chosen[0].isoformat()} -> {chosen[1].isoformat()} "
          f"({SG.number_of_nodes()} nodos)")
    visualize_graph_subset(SG, sample_size=min(500, SG.number_of_nodes()), out_file=out_file)

def ensure_runs_in_subgraph(graph_full: nx.Graph, subg: nx.Graph):
    """In a subgraph, inject missing user nodes + RUNS edges inferred from process.uid."""
    for n, data in list(subg.nodes(data=True)):
        if data.get("ntype") != "process":
            continue
        uid = data.get("uid")
        try:
            if pd.isna(uid): #skip empty
                continue
        except Exception:   # if pd.isna unavailable for type
            if uid is None:
                continue
        user_node = f"user:{uid}"
        if user_node not in subg:   # trae atributos del grafo completo si existen; si no, crea un user básico
            attrs = graph_full.nodes.get(user_node, {"ntype": "user"})
            subg.add_node(user_node, **attrs)
        edata = subg.get_edge_data(user_node, n) or {}
        has_runs = any(isinstance(a, dict) and a.get("etype") == "RUNS" for a in (edata.values() if isinstance(edata, dict) else []))
        if not has_runs:
            subg.add_edge(user_node, n, etype="RUNS", ts="na")

def visualize_ego(graph: nx.Graph, center_id: str, radius: int = 2, out_file: str = "ego.html") -> None:
    """Render an ego‑graph centered at 'center_id', ensuring RUNS edges are visible."""
    nodes = nx.ego_graph(graph, center_id, radius=radius, undirected=False).nodes()
    subg = graph.subgraph(nodes).copy()
    ensure_runs_in_subgraph(graph, subg)  # force presence of RUNS on processes
    visualize_graph_subset(subg, sample_size=subg.number_of_nodes(), out_file=out_file)

# ──────────────────────────────────────────────────────────────────────────────
# 5) Load raw log, parse into dataframes, and normalize canonical columns
# ──────────────────────────────────────────────────────────────────────────────
LOG_RAW = Path("logs_audit_raw_vf.txt")                         # input file with raw audit logs
raw_txt = LOG_RAW.read_text(encoding="utf-8", errors="ignore")
dfs = parsedata(raw_txt)                                        # parse into dict of DataFrames
print("[OK] parsedata() devolvió bloques:", list(dfs.keys()))
print("[INFO] network rows:", len(dfs.get("network", [])))

# Normalizar columnas de todos los DataFrames
for key in list(dfs.keys()):
    df = dfs[key]
    if not isinstance(df, pd.DataFrame):
        continue
    df = normalize_columns(df)

    # (filecreate) derive FilePath if absent using best available hints
    if key == "filecreate" and "FilePath" not in df.columns:
        cand = [c for c in df.columns if re.search(r'(?:^|_)name$|filename$|filepath$|fullpath$|^path$', c, re.I)]  # candidatos que suelen contener rutas o nombres de archivo
        if cand:
            df["FilePath"] = pd.NA  # elige el primer candidato no vacío por fila
            for c in cand:
                df["FilePath"] = df["FilePath"].fillna(df[c])
        if "FilePath" not in df.columns or df["FilePath"].isna().all(): # si aún no hay ruta, intenta combinar CWD + nombre
            if "cwd" in df.columns and cand:
                namecol = cand[0]
                df["FilePath"] = (df["cwd"].astype(str).str.rstrip("/") + "/" + df[namecol].astype(str).str.lstrip("/"))
            else:
                df["FilePath"] = pd.NA  # seguimos sin ruta; lo manejamos abajo

    # columnas mínimas para que el pipeline no se caiga
    if "Time" not in df.columns: df["Time"] = "na"
    if "PID" not in df.columns:  df["PID"] = pd.NA
    if "UID" not in df.columns:  df["UID"] = pd.NA

    dfs[key] = df  # ← IMPORTANTE: guardar el DF normalizado
    
# Verificación básica de columnas requeridas
REQUIRED_BY_BLOCK = {
    "process":   {"Time", "PID", "ExeName"},       # UID es útil pero no crítico
    "fileopenat":{"Time", "PID", "FilePath"},
    "filecreate":{"Time", "PID"},      # UID puede faltar según el parser, FilePath es deseable pero no crítico
    "network":   {"Time", "PID"},                  # DstIP/DstPort pueden faltar si AF_UNIX
}
for name, df in dfs.items():
    req = REQUIRED_BY_BLOCK.get(name, set())
    missing = req - set(df.columns)
    if missing:
        print(f"[WARN] Bloque '{name}' incompleto. Faltan: {missing} (continuo)")

# ──────────────────────────────────────────────────────────────────────────────
# 6) Visualization: convert NetworkX graph → PyVis HTML with controls & legend
# ──────────────────────────────────────────────────────────────────────────────
def visualize_graph_subset(graph: nx.Graph,sample_size: int = 500,out_file: str = "graph.html") -> None:
    """Genera un HTML con hasta `sample_size` nodos. Cada nodo se colorea según su tipo (ntype) usando el dict COLOR.
    La física se detiene tras la estabilización."""
    subset = list(graph.nodes)[:sample_size]
    subg = graph.subgraph(subset).copy()

    net = Network(height="650px", width="100%", bgcolor="#ffffff", directed=True)
    net.from_nx(graph.subgraph(subset))

    # nodos: tamaño por grado + tooltips + estrella si alert
    for n in net.nodes:
        gid = n["id"]
        data = subg.nodes[gid]
        ntype = data.get("ntype", "other")
        deg = subg.degree(gid)  # tamaño por grado (cap a 40)
        n["size"] = min(10 + deg * 0.5, 40)
        if ntype == "process":
            n["title"] = (
                f"<b>Process</b><br>id: {gid}<br>"
                f"exe: {data.get('exe') or data.get('ExeName')}<br>"
                f"uid: {data.get('uid')}<br>"
            )
        elif ntype == "file":
            n["title"] = f"<b>File</b><br>path: {data.get('path')}"
        elif ntype == "socket":
            n["title"] = f"<b>Socket</b><br>{data.get('ip')}:{data.get('port')}"
        elif ntype == "user":
            n["title"] = f"<b>User</b><br>uid: {gid.split(':',1)[-1]}"
        if data.get("alert"):   # estrella roja sólo si el nodo tiene alert
            n["shape"] = "star"
            n["color"] = "#FF2D00"
        else:
            n["color"] = COLOR.get(ntype,COLOR["other"])

    # aristas: colorear por alerta o tipo
    for e in net.edges:
        u, v = e["from"], e["to"]
        edata = subg.get_edge_data(u, v) or {}
        attrs_iter = edata.values() if isinstance(edata, dict) and any(isinstance(x, dict) for x in edata.values()) else [edata]
        tags_list = [a.get("alert_tags") for a in attrs_iter if isinstance(a, dict) and a.get("alert_tags")]
        has_alert = len(tags_list) > 0
        tags = tags_list[0] if has_alert else None
        etype = next((a.get("etype") for a in attrs_iter if isinstance(a, dict) and a.get("etype")), "EDGE")
        ts    = next((a.get("ts")    for a in attrs_iter if isinstance(a, dict) and a.get("ts")), None)
        if ONLY_ALERT_EDGES and not has_alert:
            e["hidden"] = True
            continue
        e["color"] = ALERT_EDGE_COLOR if has_alert else EDGE_COLOR.get(etype, "#C0C0C0")
        e["label"] = etype                 # ← etiqueta visible (acción)
        e["font"]  = {"align": "middle", "size": 8}
        info = [f"<b>{etype}</b>"]
        if ts:   info.append(f"ts={ts}")
        if tags: info.append("tags=" + " / ".join(tags))
        e["title"] = "<br>".join(info)
    
    # Physics: stabilize then freeze node positions; add legend and controls
    net.set_options("""
    {
      "physics": {
        "solver": "forceAtlas2Based",
        "stabilization": { "enabled": true, "iterations": 400 }
      },
      "interaction": { "dragNodes": false }
    }
    """)
    net.html += """
    <style>
    #legend, #inspector { position: fixed; right: 16px; background: rgba(255,255,255,.97);
      border: 1px solid #ddd; border-radius: 8px; padding: 10px; font: 12px sans-serif; z-index: 9999; }
    #legend   { bottom: 16px;  width: 240px; }
    #inspector{ top:    16px;  width: 320px; max-height: 40vh; overflow:auto; }
    .badge{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; vertical-align:middle; }
    </style>

    <div id="inspector"><b>Inspector</b><br><i>Haz click en una arista o nodo.</i></div>
    <div id="legend">
      <b>Leyenda</b><br>
      <div><span class="badge" style="background:#4C8BF5"></span>process</div>
      <div><span class="badge" style="background:#F55D4C"></span>file</div>
      <div><span class="badge" style="background:#23B5AF"></span>socket</div>
      <div><span class="badge" style="background:#FFC857"></span>user</div>
      <div><span class="badge" style="background:#3E7CB1"></span>CONNECT</div>
      <div><span class="badge" style="background:#999999"></span>EXEC</div>
      <div><span class="badge" style="background:#BDBDBD"></span>READ/WRITE/CREATE</div>
      <div><span class="badge" style="background:#D0021B"></span>alerta</div>
      <hr style="margin:8px 0">
      <label><input type="checkbox" id="onlyAlerts"> Solo aristas en alerta</label><br>
      <label><input type="checkbox" id="showRuns"> Mostrar RUNS (user→proc)</label>
    </div>

    <script>
    const edgesDS = network.body.data.edges;
    const nodesDS = network.body.data.nodes;
    function showInfo(html){ document.getElementById('inspector').innerHTML = "<b>Inspector</b><br>"+html; }
    network.on("click", function (params) {
      if (params.edges.length) {
        const e = edgesDS.get(params.edges[0]);
        showInfo("<b>Edge</b><br>" + "acción: " + (e.label||"") + "<br>" + (e.title||"") + "<br>" + "from: " + e.from + "<br>" + "to: " + e.to);
      } else if (params.nodes.length) {
        const n = nodesDS.get(params.nodes[0]);
        showInfo("<b>Node</b><br>id: " + n.id + "<br>" + (n.title||""));
      }
    });
    document.getElementById('onlyAlerts').onchange = function(){
      const only = this.checked;
      edgesDS.getIds().forEach(id=>{
        const e = edgesDS.get(id);
        const hasAlert = (e.title||"").indexOf("tags=") !== -1 || e.color === "#D0021B";
        edgesDS.update({id, hidden: only ? !hasAlert : false});
      });
    };
    document.getElementById('showRuns').onchange = function(){
      const show = this.checked;
      edgesDS.getIds().forEach(id=>{
        const e = edgesDS.get(id);
        const isRuns = (e.label||"") === "RUNS";
        edgesDS.update({id, hidden: isRuns ? !show : e.hidden});
      });
    };
    </script>
    """
    net.show(out_file)
    print(f"[OK] HTML generado: {out_file}")

# ──────────────────────────────────────────────────────────────────────────────
# 7) Build graph from parsed blocks (process/fileopenat/filecreate/network)
# ──────────────────────────────────────────────────────────────────────────────

# ─── 1) PROCESS → EXEC ───────────────────────────────────────────────────
if "process" not in dfs:
    raise RuntimeError("Bloque 'process' ausente en el log")
proc_df = fix_time(dfs["process"])
for _, row in proc_df.iterrows():
    pid, ppid, exe, uid, ts = row["PID"], row.get("PPID"), _clean(row.get("ExeName")), row.get("UID"), str(row["Time"])
    proc_node = f"proc:{pid}"
    file_node = f"file:{_clean(Path(str(exe)).name)}"
    ensure(proc_node, "process", uid=uid, exe=exe)
    ensure(file_node, "file", path=exe)
    G.nodes[proc_node].setdefault("uid", uid)
    G.nodes[proc_node].setdefault("exe", exe)
    G.add_edge(proc_node, file_node, etype="EXEC", ts=ts)
    if pd.notna(ppid) and int(ppid) > 0:
         parent_node = f"proc:{ppid}"
         ensure(parent_node, "process")                  # ← asegura tipo
         G.add_edge(parent_node, proc_node, etype="PARENT", ts=ts)
    if pd.notna(uid):
        ensure(f"user:{uid}", "user")
        if SHOW_USER_EDGES:
            G.add_edge(f"user:{uid}", proc_node, etype="RUNS", ts=ts)

# ─── 2) FILEOPENAT → READ  ────────────────────
if "fileopenat" in dfs:
    for _, row in fix_time(dfs["fileopenat"]).iterrows():
        pid, uid, fpath, ts = row["PID"], row.get("UID"), _clean(row.get("FilePath")), str(row["Time"])
        proc_node, file_node = f"proc:{pid}", f"file:{_clean(Path(str(fpath)).name)}"
        ensure(proc_node, "process", uid=uid)
        G.nodes[proc_node].setdefault("uid", uid)
        ensure(file_node, "file", path=fpath)
        G.add_edge(proc_node, file_node, etype="READ", ts=ts) # No hay flags en el log → asumimos READ por defecto

# ─── 3) FILECREATE → CREATE ──────────────────────────────────────────────
if "filecreate" in dfs:
    for idx, row in dfs["filecreate"].iterrows():
        pid, uid  = row.get("PID"), row.get("UID")
        fpath_raw = row.get("FilePath")
        ts        = str(row.get("Time", "na"))
        proc_node = f"proc:{pid}"
        ensure(proc_node, "process", uid=uid)
        G.nodes[proc_node].setdefault("uid", uid)
        if pd.isna(fpath_raw) or str(fpath_raw).strip() == "":
            file_node = f"file:<unknown-create-{pid}-{idx}>"    # placeholder estable por fila para no perder el evento
            ensure(file_node, "file", path=None)
        else:
            fpath = _clean(fpath_raw)
            file_node = f'file:{_clean(Path(str(fpath)).name)}'
            ensure(file_node, "file", path=fpath)
        G.add_edge(proc_node, file_node, etype="CREATE", ts=ts)

# ─── 4) NETWORK → CONNECT ────────────────────────────────────────────────
if "network" in dfs:
    for _, row in fix_time(dfs["network"]).iterrows():
        pid, uid, ip, port, ts = row["PID"], row.get("UID"), row["DstIP"], row["DstPort"], str(row["Time"])
        proc_node, sock_node = f"proc:{pid}", f"net:{ip}:{port}"
        ensure(proc_node, "process", uid=uid)
        G.nodes[proc_node].setdefault("uid", uid)
        ensure(sock_node, "socket", ip=ip, port=port)
        G.add_edge(proc_node, sock_node, etype="CONNECT", ts=ts)

# ──────────────────────────────────────────────────────────────────────────────
# 8) Detections (IOCs and per‑edge checks) + alert annotation
# ──────────────────────────────────────────────────────────────────────────────
from detectors import load_iocs, check_event

IOC_HASHES, IOC_IPS = load_iocs("iocs.csv")
alerts = []

for u, v, d in G.edges(data=True):
    detected = check_event(u, v, d, G, IOC_HASHES, IOC_IPS)
    if detected:
        d["alert_tags"] = detected  # ← tags en la arista
        G.nodes[u]["alert"] = True
        G.nodes[v]["alert"] = True
        alerts.append((u, v, d["etype"], detected))

print("=== ALERTAS ===")
for u, v, etype, tags in alerts[:10]:
    print(f" {etype} {u} -> {v} :: {', '.join(tags)}")
print("Total:", len(alerts))

# ──────────────────────────────────────────────────────────────────────────────
# 9) Reproducible analysis helpers and final visualizations
# ──────────────────────────────────────────────────────────────────────────────
print("\n=== ANALISIS DEMO ===")

# Proceso con alerta (si existe) → ego-subgraph
alerted_procs = [n for n, d in G.nodes(data=True) if d.get("ntype") == "process" and d.get("alert")]

if not alerted_procs:
    print(" [INFO] No hay procesos alertados; se omite análisis focalizado.")
else:
    for ap in alerted_procs[:5]:   # límite de 5 para no generar demasiados HTMLs
        print(f" [ALERT] foco en {ap}")
        visualize_ego(G, ap, radius=3, out_file=f"ego_{ap.replace(':','_')}.html")  # ego-subgrafo del proceso con alerta
        back = list(backward_tracking(ap, depth=3)) # tracking hacia atrás/adelante sólo desde el proceso con alerta
        fwd  = list(forward_tracking(ap,  depth=3))
        print(f"  Backward(3): {back[:8]}")
        print(f"  Forward (3): {fwd[:8]}")

print(f"[OK] nodos: {G.number_of_nodes():,}   aristas: {G.number_of_edges():,}")

# Grafo completo (muestra de 500 nodos)
visualize_graph_subset(G, sample_size=500, out_file="graph.html")

# Grafo en ventana temporal de ejemplo
#######   visualize_time_window(G, width_seconds=60, out_file="graph_window.html")