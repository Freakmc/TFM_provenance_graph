# AuditD Provenance Graph

Este proyecto genera un grafo de proveniencia a partir de logs crudos de `auditd`, relacionando procesos, archivos, sockets y usuarios. Permite analizar actividades sospechosas en sistemas Linux mediante trazabilidad y visualización.

---

## 🧠 ¿Qué hace?

- Analiza eventos de `auditd` en formato `--raw`
- Crea un grafo dirigido de entidades:
  - 🧍 Usuario (UID)
  - 🧠 Proceso (PID + ejecutable)
  - 📄 Archivo (ruta)
  - 🌐 Socket / red (IP:puerto)
- Añade relaciones como:
  - `RUNS`: user → process
  - `EXEC`, `READ`, `WRITE`, `CREATE`
  - `CONNECT`: conexiones de red
  - `PARENT`: jerarquía entre procesos
- Detecta comportamientos anómalos simples entre otros:
  - Binarios sospechosos
  - Conexiones como root
  - IPs maliciosas
- Visualiza el grafo con colores y alertas interactivas (`graph.html`)

---

## 🚀 Instalación

```bash
git clone https://github.com/tu_usuario/auditd-provenance.git
cd auditd-provenance
pip install -r requirements.txt
```

---

## ✏️ Requisitos adicionales

- auditd activo en la máquina
- Python 3.8 o superior
- Google Chrome (si deseas exportar PNG desde graph.html)
- Librería externa: auditdpythonparser

---

## 🕵️ Captura de LOGS

Ejecuta el siguiente script para capturar logs:

```bash
sudo ./capture.sh 60
```
Esto capturará eventos auditd desde hace 60 horas y los guardará en logs_auditd_raw.txt. En su defecto puede seguir la guía de extracción de logs (recomendado)

---

## ⚙️ Análisis

Ejecuta el script principal: provenance_from_auditd.py

Esto generará:
- ego_graph.html: visualización interactiva de las alertas
- graph.html: visualización general interactiva
- graph_window.html: subgrafo por tiempo
- Alertas básicas por consola


---

## 🔎 Verificar estructura del log

Ejecuta el script principal: check_columns.py 
Esto generará un análisis de la estructura de los logs extraidos


---

## 📁 Estructura del proyecto
```bash
.
├─ capture.sh                             ← Script de captura raw auditd
├─ provenance_from_auditd.py              ← Script principal
├─ detectors.py                           ← Script secundario para detectar alertas
├─ check_columns.py                       ← Verificador de columnas clave
├─ sample_logs                            ← Ejemplos de logs reales 
├─ requirements.txt                       ← Requisitos para el Script
├─ guia de extraccion de logs auditd.md   ← Guía de extracción de logs
└─ iocs.csv                               ← Ejemplo de archivo de iocs
```

---

## 📌 Detalles técnicos

- Basado en NetworkX + PyVis
- Cada nodo tiene tipo (ntype), UID, PID, etc.
- Alertas se colorean en rojo vivo
- Física de grafo desactivada tras estabilización para facilitar el análisis


---

##  📚 Créditos
Trabajo de TFM dirigido por Juan Tapiador

Parser auditd inspirado en auditdpythonparser


---

## 🛡️ Disclaimer
Este proyecto es educativo y orientado a análisis forense en entornos controlados. No está pensado para despliegue en producción sin mejoras adicionales de seguridad.
