# Tarea 3: SBOMs y Análisis de Vulnerabilidades 🛡️

[![Herramientas](https://img.shields.io/badge/Tools-Syft%20%7C%20Grype%20%7C%20CodeQL-blue.svg)]()
[![Jupyter Notebook](https://img.shields.io/badge/Análisis-Jupyter_Notebook-orange.svg)]()

Este proyecto automatiza por completo la evaluación de seguridad y la de deuda técnica (rastreo de Componentes de Software Abierto) de los repositorios activos de una organización mediante la generación de **SBOMs (Software Bill of Materials)** y un análisis detallado de vulnerabilidades dinámicas y estáticas.

La organización auditada para este caso de estudio es **[`anomalyco`](https://github.com/anomalyco)** (13 repositorios activos).

---

## 🏗️ Estructura del Proyecto

```plaintext
ING.Datos-tarea3/
├── data/
│   ├── repos/                 # Rutas donde se descargan los submódulos Git (repos)
│   ├── results/               # Resultados automatizados del escaneo (archivos JSON)
│   └── repos.json             # Manifiesto configurado con los target repos de anomalyco
├── nbs/
│   ├── analisis_cuantitativo.ipynb # Notebook central con el análisis de resultados  
├── scripts/                   # Automatización
│   ├── add_submodules.py      # Clona/Descarga de manera rápida (depth=1) los repos
│   ├── generate_sboms.py      # Usa 'Syft' para extraer los paquetes/dependencias
│   ├── generate_grype.py      # Usa 'Grype' para validar los CVEs y parches perdidos
│   └── generate_codeql.py     # Usa 'CodeQL' para análisis avanzado de código
└── README.md
```

## ⚙️ Pre-requisitos
Para poder correr localmente los módulos necesitarás:
- **Python 3.10+** (Librerías de análisis: `pandas`, `matplotlib`, `seaborn`)
- **Git**
- Entorno de comandos (PowerShell / Bash) con los ejecutables (CLI) de `syft`, `grype` y `codeql` instalados en su variable PATH.

## 🚀 Uso e Implementación

Para asegurar la reproducibilidad del entorno y obtener de vuelta los JSON en la carpeta `data/results/`, se ejecuta la cadena de automatización siguiendo estos pasos dentro de la raíz del proyecto:

### 1. Clonar los Repositorios
Sincroniza y descarga temporalmente los repositorios objetivo de `data/repos.json` dentro de `data/repos/`:
```bash
python scripts/add_submodules.py
```

### 2. Extracción de Software (SBOM)
Extraemos todos y cada uno de los ecosistemas (npm, cargo, python) con Syft:
```bash
python scripts/generate_sboms.py
```

### 3. Escáner de Dependencias
Escanea la versión de las librerías levantadas comparándolas con bases de datos estandarizadas de CVEs. Generará el crudo y el json normalizado `*-grype.json`:
```bash
python scripts/generate_grype.py
```
*(Se recomienda exportar `GRYPE_DB_VALIDATE_AGE=false` si se trabaja en local con una base desactualizada de más de 5 días).*

### 4. CodeQL (Opcional - Análisis Profundo de Código)
Si tu entorno soporta la inmensa carga de auto-compilado de código C++ / GO / TypeScript, puedes indexar las bases de datos:
```bash
python scripts/generate_codeql.py
```

## 📊 Análisis Cuantitativo

Toda la inteligencia extraída se decanta en un ambiente visual y reproducible. La tercera parte del proceso la puedes validar abriendo el entorno de **Jupyter Notebook**:

1. Lanza Jupyter:
```bash
jupyter notebook
```
2. Ejecuta celda a celda el archivo: **`nbs/analisis_cuantitativo.ipynb`**.

En el cuaderno encontrarás gráficos detallados comparando ecosistemas, repositorios más riesgosos y esquemas de alertas tempranas divididos en niveles Crítico, Alto, Medio y Bajo.

---
**Asignatura:** Ingeniería de Datos.
