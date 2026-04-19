import json
import subprocess
import sys
from pathlib import Path

def _run_git_command(args, cwd, error_msg):
    """Helper to run git commands"""
    try:
        subprocess.run(args, check=True, cwd=cwd, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{error_msg}: {e}")
        return False
    except FileNotFoundError:
        print("Error: 'git' command not found. Is Git installed and in your PATH?")
        sys.exit(1)

def _get_submodules_from_gitmodules(gitmodules_path):
    """Parse .gitmodules and return list of submodule paths"""
    if not gitmodules_path.exists():
        return []
    
    paths = []
    with open(gitmodules_path, 'r') as f:
        for line in f:
            if line.startswith('\tpath = '):
                path = line.split(' = ', 1)[1].strip()
                paths.append(path)
    return paths

def _get_desired_repos(repos_file):
    """Load repos from repos.json"""
    if not repos_file.exists():
        print(f"Error: Repositories file not found at {repos_file}")
        sys.exit(1)
    
    with open(repos_file, 'r') as f:
        data = json.load(f)
    
    return [repo.get("path") for repo in data.get("repositories", [])]

def remove_submodules(repo_root, paths_to_keep):
    """Remove submodules that are NOT in paths_to_keep"""
    gitmodules_path = repo_root / ".gitmodules"
    current_submodules = _get_submodules_from_gitmodules(gitmodules_path)
    
    for submodule_path in current_submodules:
        if submodule_path not in paths_to_keep:
            print(f"Removing submodule: {submodule_path}")
            
            # Remove from .git/config
            _run_git_command(
                ["git", "config", "--file", ".git/config", "--remove-section", f"submodule.{submodule_path}"],
                repo_root,
                f"Failed to remove {submodule_path} from config"
            )
            
            # Deinit the submodule
            _run_git_command(
                ["git", "submodule", "deinit", "-f", submodule_path],
                repo_root,
                f"Failed to deinit {submodule_path}"
            )
            
            # Remove from .gitmodules
            _run_git_command(
                ["git", "rm", "--cached", submodule_path],
                repo_root,
                f"Failed to remove {submodule_path} from index"
            )
            
            # Remove the directory
            submodule_dir = repo_root / submodule_path
            if submodule_dir.exists():
                import shutil
                shutil.rmtree(submodule_dir)
            
            print(f"OK Removed {submodule_path}")

def add_submodules(repo_root, repos_data):
    """
    Add submodules from repos.json
    """
    gitmodules_path = repo_root / ".gitmodules"
    
    for repo in repos_data.get("repositories", []):
        url = repo.get("url")
        path = repo.get("path")
        ref = repo.get("ref")  # Optional: branch/tag to checkout

        if not url or not path:
            print(f"Skipping invalid repository entry: {repo}")
            continue

        # Check if the submodule is already added
        already_added = False
        if gitmodules_path.exists():
            with open(gitmodules_path, 'r') as gm_file:
                if path in gm_file.read():
                    print(f"Submodule '{path}' already exists. Skipping add.")
                    already_added = True

        if not already_added:
            print(f"Adding submodule: {url} to {path}")
            if not _run_git_command(
                ["git", "submodule", "add", "--force", "--depth", "1", url, path],
                repo_root,
                f"Failed to add submodule {url}"
            ):
                continue
        
        # Checkout specific ref (branch/tag) if provided
        if ref and (repo_root / path).exists():
            print(f"Checking out {ref} in {path}...")
            if _run_git_command(
                ["git", "checkout", ref],
                repo_root / path,
                f"Failed to checkout {ref} in {path}"
            ):
                print(f"OK Checked out {ref}")

def sync_submodules():
    """
    Reads repos.json and syncs Git submodules to match.
    Adds new repos and removes repos not in repos.json.
    """
    repo_root = Path(__file__).resolve().parents[1]
    repos_file = repo_root / "data" / "repos.json"

    if not repos_file.exists():
        print(f"Error: Repositories file not found at {repos_file}")
        sys.exit(1)

    with open(repos_file, 'r') as f:
        repos_data = json.load(f)

    desired_paths = _get_desired_repos(repos_file)
    
    # First: remove submodules NOT in repos.json
    remove_submodules(repo_root, desired_paths)
    
    # Then: add submodules from repos.json
    add_submodules(repo_root, repos_data)
    
    # Finally: initialize and update all submodules
    print("\nInitializing submodule directories...")
    _run_git_command(
        ["git", "submodule", "update", "--init", "--recursive"],
        repo_root,
        "Failed to update submodules"
    )
    
    print("\nOK Submodule sync complete!")
    print("Note: Changes are NOT automatically committed. Use 'git status' to see dirty state.")

if __name__ == "__main__":
    sync_submodules()