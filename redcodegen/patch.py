"""
handle git patches on repos (SWEBench Style)
"""

import os
import logging
import subprocess
import tempfile
import shutil
from functools import cache
from typing import Sequence

from redcodegen.validator import evaluate_codebase

logger = logging.getLogger("redcodegen")


def _run_quiet(cmd: Sequence[str], cwd: str | None = None):
    """Run a subprocess quietly; log and re-raise on failure."""
    try:
        subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        details = stderr or stdout or "<no subprocess output>"
        logger.error(
            "Subprocess failed (cmd=%s, cwd=%s, rc=%s): %s",
            " ".join(cmd),
            cwd,
            exc.returncode,
            details,
        )
        raise


def _normalize_repo(repo: str) -> tuple[str, str]:
    gh_root = "https://github.com/"
    repo_name = repo
    if repo_name.startswith(gh_root):
        repo_name = repo_name[len(gh_root):]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return repo_name, gh_root + repo_name + ".git"


def clone(repo: str, path: str):
    repo_name, repo_url = _normalize_repo(repo)
    git_dir = os.path.join(path, ".git")

    if os.path.isdir(git_dir):
        return

    if os.path.exists(path):
        # Best-effort recovery for partially created cache directories.
        shutil.rmtree(path)

    _run_quiet(["git", "clone", repo_url, path])


def _repo_cache_root() -> str:
    root = os.path.join(tempfile.gettempdir(), "redcodegen_repo_cache")
    os.makedirs(root, exist_ok=True)
    return root


@cache
def get_cached_clone_path(repo: str) -> str:
    repo_name, _ = _normalize_repo(repo)
    safe_repo_name = repo_name.replace("/", "__")
    path = os.path.join(_repo_cache_root(), safe_repo_name)
    clone(repo_name, path)
    return path


def _reset_repo(repo_path: str):
    _run_quiet(["git", "reset", "--hard", "HEAD"], cwd=repo_path)
    _run_quiet(["git", "clean", "-fd"], cwd=repo_path)

def _checkout_commit(repo_path: str, commit: str):
    _run_quiet(["git", "checkout", commit], cwd=repo_path)


def apply_patch(repo_path, patch_path):
    _run_quiet(["git", "apply", patch_path], cwd=repo_path)


def patched_evaluate(repo, commit, patch, workdir=None):
    path = get_cached_clone_path(repo)
    eval_workdir = workdir or tempfile.gettempdir()
    try:
        _reset_repo(path)
        _checkout_commit(path, commit)
        patchfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            patchfile.write(patch.encode())
            patchfile.flush()
            patchfile.close()
        except Exception as e:
            patchfile.close()
            os.unlink(patchfile.name)
            raise e
        apply_patch(path, patchfile.name)
        res = evaluate_codebase(path, eval_workdir)
        return res
    finally:
        if os.path.exists(path):
            _reset_repo(path)
