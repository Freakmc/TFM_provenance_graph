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
- Detecta comportamientos anómalos simples:
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

## Requisitos adicionales:
- auditd activo en la máquina
- Python 3.8 o superior
- Google Chrome (si deseas exportar PNG desde graph.html)

CAPTURA DE LOGS
---------------

Ejecuta el siguiente script para capturar logs:

   sudo ./capture.sh 60

Esto capturará eventos auditd desde hace 60 horas y los guardará en logs_auditd_raw.txt
