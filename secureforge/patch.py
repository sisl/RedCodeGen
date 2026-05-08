"""
handle git patches on repos (SWEBench Style)
"""

import os
import subprocess
import tempfile
import shutil
from functools import cache
from typing import Sequence
from loguru import logger

from secureforge.validator import evaluate_diff


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
            "Subprocess failed (cmd={}, cwd={}, rc={}): {}",
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
    root = os.path.join(tempfile.gettempdir(), "secureforge_repo_cache")
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


def patched_evaluate(repo, commit, patch, workdir=None, skip_patch=False):
    path = get_cached_clone_path(repo)
    eval_workdir = workdir or tempfile.gettempdir()
    commit_str = str(commit)
    patch_text = "" if patch is None else (patch if isinstance(patch, str) else str(patch))
    patchfile_path = None
    try:
        _reset_repo(path)
        _checkout_commit(path, commit_str)

        if not skip_patch:
            patchfile = tempfile.NamedTemporaryFile(delete=False)
            patchfile_path = patchfile.name
            try:
                patchfile.write(patch_text.encode())
                patchfile.flush()
                patchfile.close()
            except Exception as e:
                patchfile.close()
                if patchfile_path and os.path.exists(patchfile_path):
                    os.unlink(patchfile_path)
                raise e

            apply_patch(path, patchfile_path)

        res = evaluate_diff(path, eval_workdir)
        return res
    finally:
        if patchfile_path and os.path.exists(patchfile_path):
            os.unlink(patchfile_path)
        if os.path.exists(path):
            _reset_repo(path)


def patched_changed_files(repo, commit, patch) -> list[tuple[str, str]]:
    """Apply a patch and return changed file contents.

    Returns:
        List of (relative_path, file_contents) tuples for changed text files.
    """
    path = get_cached_clone_path(repo)
    commit_str = str(commit)
    patch_text = "" if patch is None else (patch if isinstance(patch, str) else str(patch))
    patchfile_path = None
    try:
        _reset_repo(path)
        _checkout_commit(path, commit_str)

        patchfile = tempfile.NamedTemporaryFile(delete=False)
        patchfile_path = patchfile.name
        try:
            patchfile.write(patch_text.encode())
            patchfile.flush()
            patchfile.close()
        except Exception as e:
            patchfile.close()
            if patchfile_path and os.path.exists(patchfile_path):
                os.unlink(patchfile_path)
            raise e

        apply_patch(path, patchfile_path)

        diff_proc = subprocess.run(
            ["git", "-C", path, "diff", "--name-only"],
            check=True,
            capture_output=True,
            text=True,
        )
        changed_files = [line.strip() for line in diff_proc.stdout.splitlines() if line.strip()]

        results: list[tuple[str, str]] = []
        for rel_file in changed_files:
            rel_path = rel_file
            abs_path = os.path.join(path, rel_file)
            if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                logger.debug("Skipping non-text changed file: {}", rel_file)
                continue
            results.append((rel_path, content))

        return results
    finally:
        if patchfile_path and os.path.exists(patchfile_path):
            os.unlink(patchfile_path)
        if os.path.exists(path):
            _reset_repo(path)
