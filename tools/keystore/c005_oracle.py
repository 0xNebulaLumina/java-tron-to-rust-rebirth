#!/usr/bin/env python3
"""Build and execute the C005 oracle against pinned java-tron crypto classes."""
from __future__ import annotations
import argparse, base64, binascii, hashlib, json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/keystore/C005Oracle.java"
OUTPUT = ROOT / "docs/oracles/c005-keystore-fixture-manifest.v1.json"
GRADLE_VERSION = "7.6.4"
JAVA_MAJOR = "1.8"

sys.path.insert(0, str(ROOT / "tools/reference-runner"))
from java_reference_guard import install_java_reference_guard

_injected_java = os.environ.get("C029_JAVA_REFERENCE_ROOT")
_guard_root = Path(_injected_java).resolve().parent if _injected_java else ROOT
SESSION = install_java_reference_guard(_guard_root)
JAVA_TRON = SESSION.tree
JAVA_HOME = SESSION.java_home

DISPATCH = {
    **{f"C005.CROSS.{k}.{e}": "java_rust_cross_open_vectors" for k in ("SCRYPT", "PBKDF2") for e in ("EC", "SM2")},
    "C005.CROSS.PBKDF2.MISSING_DKLEN.EC": "java_rust_cross_open_vectors",
    **{f"C005.ERROR.{x}": "schema_and_decrypt_error_vectors" for x in ("WRONG_PASSWORD", "VERSION", "VERSION_INT_OVERFLOW", "MISSING_CRYPTO", "CIPHER", "KDF", "PRF")},
    **{f"C005.PASSWORD.{x}": "password_vectors" for x in ("WHITESPACE", "BOM", "EMPTY", "SHORT", "MULTILINE", "MALFORMED_UTF8")},
    **{f"C005.{x}": "filesystem_and_atomic_vectors" for x in ("NEW.INJECTED", "IMPORT.DUPLICATE", "IMPORT.OVERWRITE", "LIST.CORRUPT", "LIST.BOM", "LIST.MULTILINE", "LIST.SYMLINK", "LIST.PERMISSIONS", "LIST.OWNERSHIP", "DIRECT.SYMLINK", "DIRECT.UNQUOTED", "DIRECT.CORRUPT", "UPDATE.PASSWORD", "UPDATE.WRONG_PASSWORD", "UPDATE.DUPLICATE", "UPDATE.SYMLINK_SWAP", "WRITE.CLEANUP", "WRITE.MODE", "WINDOWS.LIMIT")},
}

def checked(command: list[str], **kwargs) -> str:
    result = SESSION.run(command, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode().strip()

def authenticate_toolchain() -> None:
    version = checked([str(JAVA_TRON / "gradlew"), "--version"], cwd=JAVA_TRON)
    if f"Gradle {GRADLE_VERSION}" not in version or not any(" ".join(line.split()).startswith(f"JVM: {JAVA_MAJOR}") for line in version.splitlines()):
        raise RuntimeError(f"C005 requires Gradle {GRADLE_VERSION} on Java {JAVA_MAJOR}")

def classpath() -> str:
    build_root = SESSION.work / "c005-gradle-build"
    init = """def c005BuildRoot = new File(%s)
allprojects { p ->
  p.buildDir = new File(c005BuildRoot, p.path == ':' ? 'root' : p.path.substring(1).replace(':', '/'))
  if (p.path == ':crypto') {
    p.afterEvaluate {
      p.tasks.register('c005RuntimeClasspath') {
        doLast { println 'C005_CLASSPATH_B64=' + p.sourceSets.main.runtimeClasspath.asPath.bytes.encodeBase64().toString() }
      }
    }
  }
}
""" % json.dumps(str(build_root))
    with tempfile.NamedTemporaryFile("w", suffix=".gradle", dir=SESSION.work, delete=False) as handle:
        handle.write(init); init_path = Path(handle.name)
    try:
        built = SESSION.gradle(["-I", str(init_path), ":protocol:jar", ":platform:jar", ":common:jar", ":crypto:classes", "-q"])
        if built.returncode:
            raise RuntimeError(built.stderr.decode("utf-8", "replace"))
        output = checked([str(JAVA_TRON / "gradlew"), "-I", str(init_path), ":crypto:c005RuntimeClasspath", "--no-daemon", "--console=plain", "-q"], cwd=JAVA_TRON)
        sentinel = "C005_CLASSPATH_B64="
        frames = [line[len(sentinel):] for line in output.splitlines() if line.startswith(sentinel)]
        if len(frames) != 1 or not frames[0]:
            raise RuntimeError("C005 Gradle classpath frame missing, duplicated, or empty")
        try:
            raw_classpath = base64.b64decode(frames[0], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise RuntimeError("C005 Gradle classpath frame is malformed") from error
        if not raw_classpath:
            raise RuntimeError("C005 Gradle classpath frame decoded to an empty value")
        for raw in raw_classpath.split(os.pathsep):
            path = Path(raw)
            if not path.exists() and path.is_relative_to(build_root) and path.parts[-2:] == ("resources", "main"):
                path.mkdir(parents=True)
            if not path.exists():
                raise RuntimeError(f"required C005 classpath entry is missing: {path}")
        return raw_classpath
    finally:
        init_path.unlink(missing_ok=True)

def compile_adapter(cp: str) -> Path:
    classes = SESSION.work / "c005-oracle-classes"
    classes.mkdir(parents=True, exist_ok=True)
    compiled = SESSION.run([str(JAVA_HOME / "bin/javac"), "-source", "8", "-target", "8", "-cp", cp, "-d", str(classes), str(SOURCE)], cwd=SESSION.work, classpath=cp)
    if compiled.returncode:
        raise RuntimeError(compiled.stderr.decode("utf-8", "replace"))
    return classes

def invoke(mode: str = "manifest", engine: str | None = None, wallet_json: str | None = None) -> dict:
    authenticate_toolchain(); cp = classpath(); classes = compile_adapter(cp)
    command = [str(JAVA_HOME / "bin/java"), "-cp", os.pathsep.join((str(classes), cp)), "C005Oracle", mode]
    if engine is not None: command.append(engine)
    if wallet_json is not None: command.append(base64.b64encode(wallet_json.encode()).decode())
    return json.loads(checked(command, cwd=SESSION.work, classpath=os.pathsep.join((str(classes), cp))).splitlines()[-1])

def generate() -> dict:
    value = invoke()
    ids = [row["id"] for row in value["vectors"]]
    if len(ids) != 37 or len(ids) != len(set(ids)) or set(ids) != set(DISPATCH):
        raise RuntimeError("Java oracle must execute exactly the 37 exhaustive C005 IDs")
    placeholders = ("placeholder", "see_c005", "not_run", "todo")
    if any(any(word in json.dumps(row).lower() for word in placeholders) for row in value["vectors"]):
        raise RuntimeError("C005 oracle emitted a placeholder vector")
    value["rust_dispatch"] = DISPATCH
    value["vectors_sha256"] = hashlib.sha256(json.dumps(value["vectors"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return value

def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--java-create", choices=("ec", "sm2"))
    parser.add_argument("--java-open", choices=("ec", "sm2"))
    parser.add_argument("--wallet-json")
    args = parser.parse_args()
    if args.java_create:
        print(json.dumps(invoke("java-create", args.java_create), sort_keys=True)); return 0
    if args.java_open:
        if args.wallet_json is None: parser.error("--java-open requires --wallet-json")
        print(json.dumps(invoke("java-open", args.java_open, args.wallet_json), sort_keys=True)); return 0
    expected = encoded(generate())
    if args.write:
        OUTPUT.write_bytes(expected); print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(DISPATCH)} executed vectors)"); return 0
    actual = OUTPUT.read_bytes() if OUTPUT.is_file() else b""
    if actual != expected:
        print("C005 oracle drift; run tools/keystore/c005_oracle.py --write", file=sys.stderr); return 1
    print(f"C005 pinned Java oracle verified: {len(DISPATCH)} executed vectors, sha256 {hashlib.sha256(actual).hexdigest()}")
    return 0
if __name__ == "__main__": raise SystemExit(main())
