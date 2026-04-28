import json
import pathlib

notebook_path = pathlib.Path('nbs/analisis_cuantitativo.ipynb')
nb = json.loads(notebook_path.read_text(encoding='utf-8'))

markdown_content = """## 5. Análisis Cualitativo: El Riesgo en la Cadena de Suministro (Caso Fake PoC Repos)

### 5.1. Contexto de la Amenaza
A principios de 2024, firmas de ciberseguridad (como Uptycs y Apiiro) reportaron una campaña maliciosa masiva en GitHub. El vector de ataque no explotaba vulnerabilidades de código tradicionales, sino el factor humano:
- Los atacantes **clonaban repositorios legítimos** de herramientas de seguridad ofensiva.
- Inyectaban malware silencioso (como *BlackCap-Grabber*) diseñado para robar credenciales, tokens y datos.
- Republicaban las herramientas alteradas usando técnicas de **typosquatting** (nombres de usuario o repositorios visualmente casi idénticos a los reales).

El objetivo de estos ataques era irónico pero letal: **infectar a los propios investigadores de seguridad e ingenieros de software** que buscaban herramientas o Pruebas de Concepto (PoCs).

### 5.2. Por qué analizamos `projectdiscovery`
La elección de analizar los repositorios de **ProjectDiscovery** (`nuclei`, `katana`, `subfinder`, `httpx`, `nuclei-templates`) no es casualidad. Con decenas de miles de estrellas (ej. >28k en `nuclei`), representan la **fuente legítima ideal** para ser imitada por atacantes. 

La extracción de SBOMs y el escaneo de dependencias (Syft + Grype) nos demostró que:
1. **Alta complejidad técnica**: Estos proyectos (principalmente en Go) poseen cientos de dependencias cruzadas. Para un investigador promedio, auditar manualmente todo el árbol de dependencias (`go.mod`/`go.sum`) antes de compilar la herramienta es humanamente imposible.
2. **Superficie de ataque heredada**: Hemos detectado vulnerabilidades reales (CVEs) provenientes de los paquetes de terceros que estas herramientas utilizan. 

### 5.3. Hallazgos vs. Vector de Ataque Real
Si bien encontrar vulnerabilidades críticas o altas en las dependencias de `nuclei` o `subfinder` representa un riesgo, el caso de los "Fake PoC" nos enseña que **el riesgo más grave es sistémico**.

* **El peligro de la confianza ciega**: Un investigador que asume que una herramienta "open source de seguridad" es segura por definición, es vulnerable. Si un atacante logra posicionar un repositorio falso llamado `projectdisccovery/nuclei` (con doble 'c') y añade un script malicioso en la secuencia de construcción, miles descargarían el malware asumiendo que es el binario oficial.
* **El vector de CI/CD**: Adicionalmente a la falsificación, existe el riesgo de un ataque directo a la cadena de suministro oficial. Si los repositorios reales de `projectdiscovery` tuviesen configuraciones inseguras en sus workflows de GitHub Actions (por ejemplo, *secrets* expuestos, permisos de escritura elevados `permissions: write-all`, o uso de Actions de terceros sin SHA fijado), un atacante ni siquiera necesitaría crear un repositorio falso. Podría comprometer el pipeline de integración y alterar los binarios compilados que se distribuyen en la sección oficial de *Releases*.

### 5.4. Conclusión Final
La ciberseguridad moderna sufre de una paradoja: **las herramientas que la comunidad utiliza para defenderse son actualmente un vector de ataque altamente lucrativo**. 

Nuestro análisis de la deuda técnica (SBOMs y CVEs) demuestra que es crítico implementar arquitecturas de **"Zero Trust"** (Cero Confianza) en el consumo de Open Source. Los equipos de ingeniería no solo deben auditar sus sistemas internos, sino exigir verificación criptográfica, reproducibilidad de builds y auditorías estrictas de CI/CD para las herramientas de terceros que introducen en sus redes."""

new_cell = {
    "cell_type": "markdown",
    "metadata": {},
    "source": [line + "\n" for line in markdown_content.split("\n")]
}
new_cell["source"][-1] = new_cell["source"][-1].rstrip("\n")

nb["cells"].append(new_cell)

notebook_path.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding='utf-8')
print("¡Celdas añadidas con éxito al notebook!")
