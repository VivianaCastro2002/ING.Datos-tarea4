"""
Auditoría de Configuraciones CI/CD (GitHub Actions)

Script que analiza los workflows de GitHub Actions en múltiples repositorios
buscando configuraciones inseguras, malas prácticas y patrones relacionados
con ataques a la cadena de suministro de software.

Reglas auditadas:
  1. action_no_sha_pin       — Acción de terceros sin SHA commit fijado
  2. excessive_permissions   — Bloque `permissions: write-all` o ausencia de permisos
  3. pull_request_target_checkout — pull_request_target + checkout de fork (pwn-request)
  4. secret_in_run           — Secretos referenciados directamente en bloques `run:`
  5. unversioned_action      — Acción referenciada con @main / @master / @latest
  6. dangerous_env_from_pr   — Variables de entorno pobladas desde contexto de PR (github.event.*)
  7. unpinned_docker          — Imágenes Docker en `uses: docker://` sin SHA digest

Proceso:
  1. Descubre repositorios en data/repos/
  2. Busca archivos YAML en .github/workflows/
  3. Aplica cada regla a cada workflow
  4. Normaliza y guarda resultados en data/results/{repo}-cicd.json

Uso:
    python scripts/generate_cicd.py                   # Análisis completo
    python scripts/generate_cicd.py --dry-run         # Ver qué se haría
    python scripts/generate_cicd.py --repos-path PATH # Rutas personalizadas

Salida:
    data/results/{repo-name}-cicd.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Iterator

import yaml  # PyYAML

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE / "data" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE / "data" / "results"
SUFIJO_CICD = "-cicd.json"

# Acciones "propias" de GitHub — no requieren SHA pin
ACCIONES_GITHUB_OFICIALES = {
    "actions/checkout",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/cache",
    "actions/setup-go",
    "actions/setup-python",
    "actions/setup-node",
    "actions/setup-java",
    "github/codeql-action/init",
    "github/codeql-action/analyze",
    "github/codeql-action/autobuild",
    "github/codeql-action/upload-sarif",
}

# Refs que se consideran no fijadas (mutable)
REFS_MUTABLE = {"main", "master", "latest", "dev", "develop", "HEAD"}

# Regex para detectar secretos en bloques run
PATRON_SECRETO_RUN = re.compile(
    r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}"
)

# Regex para detectar contextos de PR en env/with
PATRON_CONTEXTO_PR = re.compile(
    r"\$\{\{\s*github\.event\.(pull_request|issue|comment|review)\.[A-Za-z0-9_.]+\s*\}\}"
)

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reglas de auditoría
# ---------------------------------------------------------------------------

class ReglaCICD:
    """Interfaz base para reglas de auditoría CI/CD."""

    id: str
    descripcion: str
    severidad: str  # critical | high | medium | low | info

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        """Devuelve lista de hallazgos para este workflow."""
        raise NotImplementedError


class ReglaActionNoShaPinned(ReglaCICD):
    """Detecta acciones de terceros referenciadas por rama/tag mutable en lugar de SHA."""

    id = "action_no_sha_pin"
    descripcion = (
        "Acción de tercero sin SHA commit fijado. "
        "Un atacante que comprometa el repositorio de la acción puede inyectar código malicioso "
        "sin cambiar el tag, como ocurrió en el ataque a tj-actions/changed-files (2025)."
    )
    severidad = "high"

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if not uses or uses.startswith("./.github"):
                    continue
                accion, _, ref = uses.partition("@")
                if not ref:
                    continue
                # Es SHA si tiene 40 caracteres hex
                es_sha = bool(re.fullmatch(r"[0-9a-f]{40}", ref))
                # Omitir acciones oficiales de GitHub (son de confianza y usan versiones semver)
                es_oficial = any(accion.startswith(a) for a in ACCIONES_GITHUB_OFICIALES)
                # También permitir acciones de la propia organización
                es_misma_org = accion.startswith("projectdiscovery/")
                if not es_sha and not es_oficial and not es_misma_org:
                    hallazgos.append(_hallazgo(
                        regla=self.id,
                        severidad=self.severidad,
                        archivo=str(workflow_path.name),
                        job=job_name,
                        step=step.get("name", uses),
                        detalle=f"uses: {uses}  →  ref '{ref}' no es SHA",
                        descripcion=self.descripcion,
                    ))
        return hallazgos


class ReglaPermisoExcesivo(ReglaCICD):
    """Detecta bloques `permissions: write-all` o ausencia total de bloque de permisos."""

    id = "excessive_permissions"
    descripcion = (
        "Workflow sin restricción de permisos o con write-all. "
        "Permisos excesivos amplían el radio de daño si el workflow es comprometido "
        "(patrón documentado en el ecosistema GitHub Actions 2024-2026)."
    )
    severidad = "medium"

    # Permisos de escritura que se consideran riesgosos a nivel top-level
    PERMISOS_ESCRITURA_RIESGOSOS = {
        "contents": "write",
        "packages": "write",
        "actions": "write",
        "id-token": "write",
        "pull-requests": "write",
        "issues": "write",
        "deployments": "write",
        "security-events": "write",
    }

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        permisos_top = workflow_data.get("permissions")

        if permisos_top == "write-all":
            hallazgos.append(_hallazgo(
                regla=self.id,
                severidad="high",
                archivo=str(workflow_path.name),
                job="(global)",
                step="permissions",
                detalle="permissions: write-all a nivel de workflow",
                descripcion=self.descripcion,
            ))
        elif permisos_top is None:
            # Sin bloque de permisos — hereda permisos del repo (posiblemente write)
            hallazgos.append(_hallazgo(
                regla=self.id,
                severidad=self.severidad,
                archivo=str(workflow_path.name),
                job="(global)",
                step="permissions",
                detalle="No se define bloque 'permissions' a nivel de workflow (hereda del repositorio)",
                descripcion=self.descripcion,
            ))

        # Verificar permisos excesivos por job
        for job_name, job in _iterar_jobs(workflow_data):
            job_perms = job.get("permissions")
            if job_perms == "write-all":
                hallazgos.append(_hallazgo(
                    regla=self.id,
                    severidad="high",
                    archivo=str(workflow_path.name),
                    job=job_name,
                    step="permissions",
                    detalle=f"Job '{job_name}' tiene permissions: write-all",
                    descripcion=self.descripcion,
                ))
        return hallazgos


class ReglaPullRequestTargetCheckout(ReglaCICD):
    """Detecta el patrón 'pwn-request': pull_request_target + checkout de fork."""

    id = "pull_request_target_checkout"
    descripcion = (
        "Workflow disparado por pull_request_target que hace checkout del código del fork. "
        "Permite que un atacante externo ejecute código arbitrario con los secretos del repositorio base "
        "(CVE pattern documentado, relacionado con ataques a la cadena de suministro)."
    )
    severidad = "critical"

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        triggers = workflow_data.get("on", {})
        if isinstance(triggers, str):
            triggers = {triggers: {}}
        if "pull_request_target" not in triggers:
            return hallazgos

        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if "checkout" in uses:
                    ref_param = step.get("with", {}).get("ref", "")
                    # Si el ref viene del contexto del PR, es vulnerable
                    if "github.event.pull_request" in str(ref_param):
                        hallazgos.append(_hallazgo(
                            regla=self.id,
                            severidad=self.severidad,
                            archivo=str(workflow_path.name),
                            job=job_name,
                            step=step.get("name", uses),
                            detalle=(
                                f"pull_request_target + checkout con ref='{ref_param}'"
                                " — posible ejecución de código de fork con secretos del repo base"
                            ),
                            descripcion=self.descripcion,
                        ))
        return hallazgos


class ReglaSecretoEnRun(ReglaCICD):
    """Detecta secretos interpolados directamente en bloques `run:`."""

    id = "secret_in_run"
    descripcion = (
        "Secreto referenciado directamente en un bloque 'run:'. "
        "Puede quedar expuesto en logs del runner si el comando falla o si se activa verbose. "
        "Patrón relacionado con la exposición de secretos en workflows comprometidos (tj-actions 2025)."
    )
    severidad = "high"

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                run_block = step.get("run", "")
                if not run_block:
                    continue
                matches = PATRON_SECRETO_RUN.findall(str(run_block))
                for match in matches:
                    hallazgos.append(_hallazgo(
                        regla=self.id,
                        severidad=self.severidad,
                        archivo=str(workflow_path.name),
                        job=job_name,
                        step=step.get("name", "(sin nombre)"),
                        detalle=f"Secreto interpolado en run: {match}",
                        descripcion=self.descripcion,
                    ))
        return hallazgos


class ReglaActionSinVersion(ReglaCICD):
    """Detecta acciones referenciadas con @main, @master, @latest u otras ramas mutables."""

    id = "unversioned_action"
    descripcion = (
        "Acción referenciada por rama mutable (@main, @master, @latest). "
        "Cualquier commit posterior en esa rama modifica el comportamiento del workflow "
        "sin revisión explícita — vector de supply-chain attack."
    )
    severidad = "high"

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if not uses or uses.startswith("./.github"):
                    continue
                _, _, ref = uses.partition("@")
                if ref.lower() in REFS_MUTABLE:
                    hallazgos.append(_hallazgo(
                        regla=self.id,
                        severidad=self.severidad,
                        archivo=str(workflow_path.name),
                        job=job_name,
                        step=step.get("name", uses),
                        detalle=f"uses: {uses}  →  ref mutable '{ref}'",
                        descripcion=self.descripcion,
                    ))
        return hallazgos


class ReglaDangerousEnvFromPR(ReglaCICD):
    """Detecta variables de entorno construidas con datos no sanitizados de contexto de PR."""

    id = "dangerous_env_from_pr"
    descripcion = (
        "Variable de entorno construida con datos del evento de PR sin sanitizar. "
        "Un atacante puede inyectar comandos arbitrarios mediante el título o cuerpo del PR "
        "(GitHub Script Injection — documentado en múltiples CVEs de Actions 2024)."
    )
    severidad = "high"

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                env_block = step.get("env", {}) or {}
                for var_name, var_value in env_block.items():
                    valor_str = str(var_value)
                    matches = PATRON_CONTEXTO_PR.findall(valor_str)
                    if matches:
                        hallazgos.append(_hallazgo(
                            regla=self.id,
                            severidad=self.severidad,
                            archivo=str(workflow_path.name),
                            job=job_name,
                            step=step.get("name", "(sin nombre)"),
                            detalle=(
                                f"env.{var_name} usa contexto de PR no sanitizado: {valor_str[:100]}"
                            ),
                            descripcion=self.descripcion,
                        ))
        return hallazgos


class ReglaDockerSinDigest(ReglaCICD):
    """Detecta imágenes Docker referenciadas sin SHA digest."""

    id = "unpinned_docker"
    descripcion = (
        "Imagen Docker referenciada sin SHA digest fijo. "
        "Un atacante que controle el registro puede cambiar la imagen asociada al tag "
        "sin modificar el workflow — vector de supply chain attack."
    )
    severidad = "medium"

    PATRON_DOCKER = re.compile(r"^docker://(.+)$")

    def evaluar(self, workflow_path: Path, workflow_data: dict) -> list[dict]:
        hallazgos = []
        for job_name, job in _iterar_jobs(workflow_data):
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                m = self.PATRON_DOCKER.match(uses)
                if not m:
                    continue
                imagen = m.group(1)
                # SHA digest tiene formato @sha256:...
                if "@sha256:" not in imagen:
                    hallazgos.append(_hallazgo(
                        regla=self.id,
                        severidad=self.severidad,
                        archivo=str(workflow_path.name),
                        job=job_name,
                        step=step.get("name", uses),
                        detalle=f"Docker image sin digest: {imagen}",
                        descripcion=self.descripcion,
                    ))
        return hallazgos


# ---------------------------------------------------------------------------
# Analizador principal
# ---------------------------------------------------------------------------

REGLAS: list[ReglaCICD] = [
    ReglaActionNoShaPinned(),
    ReglaPermisoExcesivo(),
    ReglaPullRequestTargetCheckout(),
    ReglaSecretoEnRun(),
    ReglaActionSinVersion(),
    ReglaDangerousEnvFromPR(),
    ReglaDockerSinDigest(),
]


class CICDAuditor:
    """Audita configuraciones de CI/CD (GitHub Actions) en múltiples repositorios."""

    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.dry_run = False

    def discover_repositories(self) -> list[str]:
        """Devuelve lista de rutas relativas de repositorios."""
        if not self.repos_path.exists():
            raise FileNotFoundError(f"Directorio de repos no encontrado: {self.repos_path}")
        if not self.repos_path.is_dir():
            raise NotADirectoryError(f"La ruta no es un directorio: {self.repos_path}")

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )
        if not repositorios:
            LOGGER.warning("No se encontraron repositorios en %s", self.repos_path)
        return repositorios

    def discover_workflows(self, repo_path: Path) -> list[Path]:
        """Descubre archivos YAML de workflows en .github/workflows/."""
        workflows_dir = repo_path / ".github" / "workflows"
        if not workflows_dir.exists():
            return []
        return sorted(
            p for p in workflows_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
        )

    def audit_workflow(self, workflow_path: Path) -> list[dict]:
        """Carga y audita un workflow YAML, devolviendo lista de hallazgos."""
        try:
            texto = workflow_path.read_text(encoding="utf-8", errors="replace")
            workflow_data = yaml.safe_load(texto) or {}
        except Exception as e:
            LOGGER.warning("No se pudo parsear %s: %s", workflow_path.name, e)
            return []

        if not isinstance(workflow_data, dict):
            return []

        hallazgos = []
        for regla in REGLAS:
            try:
                hallazgos.extend(regla.evaluar(workflow_path, workflow_data))
            except Exception as e:
                LOGGER.warning(
                    "Error al aplicar regla '%s' en %s: %s",
                    regla.id, workflow_path.name, e
                )
        return hallazgos

    def audit_repository(self, repo_path_rel: str) -> dict:
        """Audita todos los workflows de un repositorio y devuelve análisis normalizado."""
        ruta_repo = self.project_root / repo_path_rel
        repo_name = ruta_repo.name

        workflows = self.discover_workflows(ruta_repo)
        LOGGER.info(
            "  %s: %d workflow(s) encontrado(s)",
            repo_name, len(workflows)
        )

        todos_hallazgos: list[dict] = []
        workflows_analizados = []

        for wf_path in workflows:
            hallazgos = self.audit_workflow(wf_path)
            todos_hallazgos.extend(hallazgos)
            workflows_analizados.append({
                "nombre": wf_path.name,
                "hallazgos": len(hallazgos),
            })
            if hallazgos:
                LOGGER.info(
                    "    %s → %d hallazgo(s)",
                    wf_path.name, len(hallazgos)
                )

        return self._normalizar_resultado(repo_name, workflows_analizados, todos_hallazgos)

    def save_analysis(self, repo_name: str, analysis: dict) -> Path:
        """Guarda el análisis en el directorio de salida."""
        if not repo_name:
            raise ValueError("El nombre del repositorio no puede estar vacío.")
        self.output_path.mkdir(parents=True, exist_ok=True)
        ruta_salida = self.output_path / f"{repo_name}{SUFIJO_CICD}"
        contenido = json.dumps(analysis, ensure_ascii=False, indent=2)
        ruta_salida.write_text(contenido, encoding="utf-8")
        LOGGER.info(
            "Análisis CI/CD guardado en %s",
            ruta_salida.relative_to(self.project_root)
        )
        return ruta_salida

    def run(self):
        """Orquesta el análisis de todos los repositorios."""
        repositorios = self.discover_repositories()

        if not repositorios:
            LOGGER.warning("No hay repositorios para analizar. Terminando.")
            return

        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de salida existe pero no es un directorio: {self.output_path}"
            )
        self.output_path.mkdir(parents=True, exist_ok=True)

        repos_analizados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path
            LOGGER.info(
                "[%d/%d] Auditando CI/CD en %s...",
                indice, len(repositorios), repo_path
            )

            if self.dry_run:
                workflows = self.discover_workflows(ruta_repo)
                salida = self.output_path / f"{ruta_repo.name}{SUFIJO_CICD}"
                LOGGER.info(
                    "  Dry-run: %d workflow(s) → generaría %s",
                    len(workflows),
                    salida.relative_to(self.project_root)
                )
                omitidos += 1
                continue

            try:
                analysis = self.audit_repository(repo_path)
                self.save_analysis(ruta_repo.name, analysis)
                repos_analizados += 1
                archivos_generados += 1
            except Exception as e:
                errores += 1
                LOGGER.error(
                    "Error al auditar %s: %s", repo_path, e
                )

        LOGGER.info(
            "Resumen | total_repos=%d | repos_analizados=%d | "
            "archivos_generados=%d | omitidos=%d | errores=%d",
            len(repositorios), repos_analizados,
            archivos_generados, omitidos, errores,
        )

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _normalizar_resultado(
        self,
        repo_name: str,
        workflows_analizados: list[dict],
        hallazgos: list[dict],
    ) -> dict:
        """Construye el dict de resultado normalizado."""
        conteo_severidad = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        conteo_por_regla: dict[str, int] = {}

        for h in hallazgos:
            sev = h.get("severidad", "info").lower()
            if sev in conteo_severidad:
                conteo_severidad[sev] += 1
            regla = h.get("regla", "unknown")
            conteo_por_regla[regla] = conteo_por_regla.get(regla, 0) + 1

        return {
            "repositorio": repo_name,
            "total_workflows": len(workflows_analizados),
            "total_hallazgos": len(hallazgos),
            "hallazgos_por_severidad": conteo_severidad,
            "hallazgos_por_regla": conteo_por_regla,
            "workflows_analizados": workflows_analizados,
            "hallazgos": hallazgos,
        }


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def _iterar_jobs(workflow_data: dict) -> Iterator[tuple[str, dict]]:
    """Itera sobre los jobs de un workflow de forma segura."""
    jobs = workflow_data.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if isinstance(job, dict):
            yield job_name, job


def _hallazgo(
    regla: str,
    severidad: str,
    archivo: str,
    job: str,
    step: str,
    detalle: str,
    descripcion: str,
) -> dict:
    """Construye un dict de hallazgo normalizado."""
    return {
        "regla": regla,
        "severidad": severidad,
        "archivo": archivo,
        "job": job,
        "step": step,
        "detalle": detalle,
        "descripcion": descripcion,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audita workflows de GitHub Actions en busca de configuraciones inseguras."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Ruta al directorio que contiene los repositorios a auditar.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio donde se guardarán los resultados.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra qué repositorios se auditarían sin ejecutar el análisis.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    auditor = CICDAuditor(args.repos_path, args.output_path)
    auditor.dry_run = args.dry_run

    try:
        auditor.run()
    except Exception as error:
        LOGGER.error("Error fatal: %s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
