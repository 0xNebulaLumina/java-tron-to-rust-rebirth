#!/usr/bin/env python3
"""Fail-closed immutable access to the pinned java-tron reference."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

PINNED_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
PINNED_JAVA_HOME = Path("/usr/lib/jvm/java-8-openjdk-amd64")


class JavaReferenceError(RuntimeError):
    """The Java reference or a capture-time identity check failed."""


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.CalledProcessError) as error:
        output = getattr(error, "output", "")
        detail = f": {output.strip()}" if output else ""
        raise JavaReferenceError(f"git {' '.join(args)} failed{detail}") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_digest(root: Path, paths: Iterable[Path] | None = None) -> str:
    digest = hashlib.sha256()
    candidates = paths if paths is not None else (
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    )
    for relative_path in sorted(candidates, key=lambda path: path.as_posix()):
        path = root / relative_path
        relative = relative_path.as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        if not path.exists() and not path.is_symlink():
            digest.update(b"M")
        elif path.is_symlink():
            value = os.readlink(path).encode()
            digest.update(b"L" + len(value).to_bytes(8, "big") + value)
        else:
            digest.update(b"F" + path.stat().st_size.to_bytes(8, "big"))
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
    return digest.hexdigest()


def verify_java_reference(root: Path, *, phase: str = "check") -> str:
    """Require one exact stage-0 gitlink and a pristine matching submodule."""
    root = root.resolve()
    java_tron = root / "java-tron"
    tree_rows = _git(root, "ls-tree", "HEAD", "--", "java-tron").splitlines()
    if len(tree_rows) != 1:
        raise JavaReferenceError(
            f"{phase}: expected exactly one superproject java-tron tree row"
        )
    fields = tree_rows[0].split(None, 3)
    if (
        len(fields) != 4
        or fields[:2] != ["160000", "commit"]
        or fields[3] != "java-tron"
    ):
        raise JavaReferenceError(
            f"{phase}: java-tron is not an exact superproject gitlink"
        )
    gitlink = fields[2]
    if gitlink != PINNED_REVISION:
        raise JavaReferenceError(
            f"{phase}: superproject java-tron gitlink {gitlink} != pinned {PINNED_REVISION}"
        )

    index_rows = _git(root, "ls-files", "--stage", "--", "java-tron").splitlines()
    if len(index_rows) != 1:
        raise JavaReferenceError(
            f"{phase}: expected exactly one stage-0 java-tron index row"
        )
    index_fields = index_rows[0].split(None, 3)
    if (
        len(index_fields) != 4
        or index_fields[0] != "160000"
        or index_fields[1] != gitlink
        or index_fields[2] != "0"
        or index_fields[3] != "java-tron"
    ):
        raise JavaReferenceError(
            f"{phase}: malformed, unmerged, or mismatched java-tron index row"
        )

    head = _git(java_tron, "rev-parse", "HEAD").strip()
    if head != gitlink:
        raise JavaReferenceError(f"{phase}: java-tron HEAD {head} != gitlink {gitlink}")
    porcelain = _git(
        java_tron, "status", "--porcelain=v1", "--untracked-files=all"
    ).strip()
    if porcelain:
        raise JavaReferenceError(
            f"{phase}: java-tron has tracked or nonignored untracked changes:\n{porcelain}"
        )
    return gitlink


def classpath_identity(classpath: str) -> list[dict[str, object]]:
    """Hash every classpath file, JAR, and file within class directories."""
    rows: list[dict[str, object]] = []
    for raw in classpath.split(os.pathsep):
        path = Path(raw).resolve()
        if not path.exists():
            raise JavaReferenceError(f"classpath entry is missing: {path}")
        if path.is_file():
            rows.append(
                {
                    "path": str(path),
                    "kind": "jar" if path.suffix == ".jar" else "file",
                    "sha256": _sha256(path),
                }
            )
        else:
            files = [
                {
                    "path": item.relative_to(path).as_posix(),
                    "sha256": _sha256(item),
                }
                for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file())
            ]
            rows.append(
                {
                    "path": str(path),
                    "kind": "directory",
                    "files": files,
                    "sha256": hashlib.sha256(
                        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                }
            )
    return rows


class JavaReferenceSession:
    """Private Git-object materialization and authenticated Java process session."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.revision = verify_java_reference(self.root, phase="before materialization")
        self._temporary = tempfile.TemporaryDirectory(prefix="java-reference-")
        self.work = Path(self._temporary.name)
        self.tree = self.work / "java-tron"
        self.tree.mkdir()
        archive = subprocess.Popen(
            [
                "git", "-C", str(self.root / "java-tron"), "archive",
                "--format=tar", self.revision,
            ],
            stdout=subprocess.PIPE,
        )
        assert archive.stdout is not None
        with tarfile.open(fileobj=archive.stdout, mode="r|") as bundle:
            bundle.extractall(self.tree, filter="data")
        if archive.wait() != 0:
            raise JavaReferenceError("git archive failed while materializing java-tron")

        self.source_paths = tuple(
            sorted(
                (
                    path.relative_to(self.tree)
                    for path in self.tree.rglob("*")
                    if path.is_file() or path.is_symlink()
                ),
                key=lambda path: path.as_posix(),
            )
        )
        self.source_tree_sha256 = _tree_digest(self.tree, self.source_paths)
        tree_listing = _git(
            self.root / "java-tron", "ls-tree", "-r", "--full-tree", self.revision
        )
        self.git_tree_sha256 = hashlib.sha256(tree_listing.encode()).hexdigest()
        self.java_home = PINNED_JAVA_HOME
        if not (self.java_home / "bin/java").is_file():
            raise JavaReferenceError(f"pinned JDK 8 is missing: {self.java_home}")
        self.env = {
            "PATH": f"{self.java_home / 'bin'}:/usr/bin:/bin",
            "JAVA_HOME": str(self.java_home),
            "HOME": str(self.work / "home"),
            "GRADLE_USER_HOME": str(self.work / "gradle-home"),
            "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        }
        self.identity = {
            "java_revision": self.revision,
            "git_tree_sha256": self.git_tree_sha256,
            "source_tree_sha256": self.source_tree_sha256,
            "jdk_home": str(self.java_home),
        }

    def close(self) -> None:
        global _INSTALLED
        self._temporary.cleanup()
        if _INSTALLED is self:
            _INSTALLED = None

    def __enter__(self) -> "JavaReferenceSession":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def guard(self, *, phase: str, classpath: str | None = None) -> dict[str, object]:
        verify_java_reference(self.root, phase=phase)
        if _tree_digest(self.tree, self.source_paths) != self.source_tree_sha256:
            raise JavaReferenceError(f"{phase}: immutable Java materialization changed")
        result: dict[str, object] = dict(self.identity)
        if classpath is not None:
            result["classpath"] = classpath_identity(classpath)
        return result

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: int = 1800,
        classpath: str | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        before = self.guard(phase="immediately before Java process", classpath=classpath)
        completed = subprocess.run(
            list(argv), cwd=cwd or self.tree, env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        after = self.guard(phase="immediately after Java process", classpath=classpath)
        if before != after:
            raise JavaReferenceError("Java reference identity changed across process")
        if check and completed.returncode:
            raise subprocess.CalledProcessError(
                completed.returncode, argv, completed.stdout, completed.stderr
            )
        return completed

    def gradle(
        self, args: Sequence[str], *, timeout: int = 1800
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            [
                str(self.tree / "gradlew"), "--no-daemon", "--no-build-cache",
                "--console=plain", "--dependency-verification=strict", *args,
            ],
            cwd=self.tree,
            timeout=timeout,
        )


def atomic_write_json(path: Path, document: object) -> None:
    """Durably replace a JSON member/batch without exposing partial contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


_INSTALLED: JavaReferenceSession | None = None


def install_java_reference_guard(root: Path) -> JavaReferenceSession:
    """Install and return the process-wide immutable reference session."""
    global _INSTALLED
    if _INSTALLED is None:
        _INSTALLED = JavaReferenceSession(root)
    elif _INSTALLED.root != root.resolve():
        raise JavaReferenceError("Java reference guard already installed for another root")
    return _INSTALLED


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--phase", default="standalone check")
    args = parser.parse_args()
    verify_java_reference(args.root, phase=args.phase)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
