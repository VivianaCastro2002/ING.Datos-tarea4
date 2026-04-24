# Tarea 4: Análisis de Vulnerabilidades en Repositorios de Software 🛡️

[![Herramientas](https://img.shields.io/badge/Tools-Syft%20%7C%20Grype%20%7C%20CodeQL-blue.svg)](https://github.com/anchore)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub_Actions_Audit-yellow.svg)]()
[![Jupyter Notebook](https://img.shields.io/badge/Análisis-Jupyter_Notebook-orange.svg)]()

Este proyecto evalúa el estado de seguridad de una organización en GitHub a través de tres dimensiones integradas: **análisis de código fuente**, **inventario de dependencias** y **revisión de configuraciones CI/CD**. Los resultados se consolidan en un dataset estructurado y se analizan en un notebook con dimensiones cuantitativa y cualitativa.

La organización auditada es **[`projectdiscovery`](https://github.com/projectdiscovery)** — los 5 repositorios más populares por ⭐ estrellas.

---

## 🎯 Justificación de la Organización

**ProjectDiscovery** fue seleccionada por su conexión directa con el caso de estudio **"GitHub Fake PoC Repos" (2024)**:

- Sus herramientas (`nuclei`, `httpx`, `subfinder`, etc.) son las que los atacantes **clonan, inyectan con malware y redistribuyen** haciéndose pasar por versiones legítimas — exactamente el patrón documentado por Uptycs y Apiiro.
- Alta relevancia observable: `nuclei` supera los **28,000 ⭐**, con uso masivo en la comunidad de seguridad ofensiva y defensiva.
- Los repos son herramientas de código real en Go, lo que permite un análisis completo de las tres dimensiones (código, dependencias, CI/CD).

| Repo | ⭐ Stars | Lenguaje | Branch |
|---|---|---|---|
| `nuclei` | 28,056 | Go | `dev` |
| `katana` | 16,575 | Go | `dev` |
| `subfinder` | 13,496 | Go | `dev` |
| `nuclei-templates` | 12,226 | JavaScript/YAML | `main` |
| `httpx` | 9,849 | Go | `dev` |

---

## 🏗️ Estructura del Proyecto

```plaintext
ING.Datos-tarea4/
├── data/
│   ├── repos/                 # Repositorios clonados como submódulos Git
│   ├── results/               # JSONs generados por el pipeline de análisis
│   └── repos.json             # Manifiesto con los 5 repos objetivo de projectdiscovery
├── nbs/
│   └── analisis_cuantitativo.ipynb  # Notebook con análisis cuantitativo y cualitativo
├── scripts/                   # Pipeline de automatización
│   ├── add_submodules.py      # Clona/sincroniza los repos objetivo (depth=1)
│   ├── generate_sboms.py      # Genera SBOMs con Syft (inventario de dependencias)
│   ├── generate_grype.py      # Escanea CVEs con Grype y normaliza resultados
│   ├── generate_cicd.py       # Audita workflows de GitHub Actions por configuraciones inseguras
│   └── generate_codeql.py     # Análisis estático avanzado con CodeQL (opcional)
└── README.md
```

---

## ⚙️ Pre-requisitos

1. **Python 3.10+**: Instala las dependencias necesarias (`pandas`, `matplotlib`, `seaborn`, `pyyaml`, `jupyter`):
   ```bash
   pip install -r requirements.txt
   ```
2. **Git**: Necesario para clonar los repositorios.
3. **Syft y Grype**: Herramientas de CLI (CLI tools) para generar los SBOMs y descubrir vulnerabilidades.
   - En **Windows** (usando PowerShell / WinGet):
     ```powershell
     winget install Anchore.Syft
     winget install Anchore.Grype
     ```
     *(Es necesario **reiniciar la terminal** después para actualizar el PATH)*
   - En **macOS/Linux**:
     ```bash
     curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
     curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
     ```

---

## 🚀 Pipeline de Análisis

**Importante:** Debes correr los pasos del pipeline al menos una vez para generar los datos que consumirá el Jupyter Notebook. Ejecuta en orden desde la raíz del proyecto:

### 1. Clonar los Repositorios
Sincroniza los repos de `data/repos.json` en `data/repos/` (elimina anteriores si los hay):
```bash
python scripts/add_submodules.py
```

### 2. Extracción de Software (SBOM)
Genera un inventario completo de paquetes y dependencias por ecosistema (Go, npm, pip…):
```bash
python scripts/generate_sboms.py
```

### 3. Escáner de Dependencias (CVEs)
Compara las versiones de las librerías contra bases de datos de CVEs estandarizadas. Genera `*-grype-raw.json` y `*-grype.json` normalizado:
```bash
python scripts/generate_grype.py
```
*(Exportar `GRYPE_DB_VALIDATE_AGE=false` si la base de datos local tiene más de 5 días.)*

### 4. Auditoría de CI/CD
Analiza los workflows de GitHub Actions (`.github/workflows/*.yml`) en busca de configuraciones inseguras: acciones sin SHA fijado, permisos excesivos, secretos expuestos en logs, `pull_request_target` con checkout, entre otros:
```bash
python scripts/generate_cicd.py
```

### 5. CodeQL — Análisis Estático (Opcional)
Indexa y analiza el código fuente Go en busca de vulnerabilidades de código. Requiere recursos significativos:
```bash
python scripts/generate_codeql.py
```

---

## 📊 Análisis en Jupyter Notebook

> ⚠️ **REQUISITO PREVIO**: Asegúrate de haber ejecutado los scripts del pipeline (al menos los pasos 1, 2 y 3) antes de abrir el notebook. Si no lo haces, Pandas arrojará un error `KeyError: 'repositorio'` porque no encontrará los JSONs en la carpeta `data/results/`.

Una vez generados los resultados en `data/results/`, analízalos abriendo el entorno de Jupyter:

```bash
jupyter notebook
```

Abre y ejecuta celda a celda: **`nbs/analisis_cuantitativo.ipynb`**

El notebook contiene:
- **Dimensión cuantitativa**: distribución de CVEs por severidad, heatmap comparativo entre repos, ecosistemas más vulnerables, top paquetes con mayor riesgo, hallazgos CI/CD por tipo de regla.
- **Dimensión cualitativa**: interpretación de patrones, relación con el caso Fake PoC Repos (2024), análisis de causas locales vs. sistémicas del ecosistema Go/GitHub Actions, y conclusiones sobre la cadena de suministro de software.

---

**Integrantes:**
- Belén Bravo
- Viviana Castro
- Valentina Cifuentes

**Asignatura:** Ingeniería de Datos.

