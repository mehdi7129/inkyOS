#!/usr/bin/env bash
# Exercise real Linux entropy/UTS APIs only on private fixture roots in the builder.
set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
overlay_dir="$(dirname -- "$script_dir")/overlay"
if [[ $# == 2 && $1 == --overlay ]]; then
  overlay_dir=$2
elif [[ $# != 0 ]]; then
  echo 'Usage: sudo bash smoke-firstboot-linux.sh [--overlay DIRECTORY]' >&2
  exit 2
fi
if [[ $(uname -s) != Linux || $(uname -m) != aarch64 || $EUID != 0 ]] ||
   [[ ! -f /var/lib/inkyos-build/owner || -L /var/lib/inkyos-build/owner ]] ||
   [[ $(cat /var/lib/inkyos-build/owner) != inkyos-builder-v1 ]]; then
  echo '{"checks":{"linux_arm64_builder":false},"passed":false}'
  echo 'Run as root only inside the marked ARM64 Linux builder.' >&2
  exit 2
fi
for tool in python3 unshare; do
  command -v "$tool" >/dev/null || { echo 'Required smoke-test tool is unavailable.' >&2; exit 2; }
done
firstboot_file="$overlay_dir/usr/local/lib/inkyos/firstboot.py"
[[ -f $firstboot_file && ! -L $firstboot_file ]] || {
  echo 'Expected a regular firstboot.py in the selected overlay.' >&2; exit 2;
}

# The parent owns fixture cleanup even if the namespaced child fails or times out.
# -B prevents importing the overlay from creating __pycache__ in the source tree.
exec python3 -B - "$firstboot_file" <<'PY'
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile


CHILD = r'''
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys

names = (
    "private_uts_namespace", "kernel_entropy", "runtime_hostname_applied",
    "two_distinct_identities", "repeat_stable_without_entropy",
    "private_permissions", "machine_id_unchanged", "fixture_files_reconciled",
)
checks = dict.fromkeys(names, False)
try:
    source, scratch_path, parent_uts = sys.argv[1:]
    # This check must pass before the first real sethostname call.
    checks["private_uts_namespace"] = os.readlink("/proc/self/ns/uts") != parent_uts
    if not checks["private_uts_namespace"]:
        raise RuntimeError("UTS isolation required")
    scratch = Path(scratch_path)
    info = scratch.lstat()
    if (scratch.resolve().parent != Path("/tmp").resolve()
            or not scratch.name.startswith("inkyos-firstboot-smoke-")
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("Private fixture directory required")
    spec = importlib.util.spec_from_file_location("inkyos_firstboot_smoke", source)
    firstboot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(firstboot)
    roots = []
    sentinel = "systemd-owned-fixture-sentinel\n"
    for name in ("first", "second"):
        root = scratch / name
        root.mkdir(mode=0o700)
        (root / "etc").mkdir(mode=0o755)
        (root / "var/lib").mkdir(mode=0o755, parents=True)
        for filename, content in (
            ("hostname", "inky-unconfigured\n"),
            ("hosts", "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 inky-unconfigured\n"),
            ("machine-id", sentinel),
        ):
            path = root / "etc" / filename
            path.write_text(content)
            path.chmod(0o644)
        roots.append(root)

    def runtime_hostname(value):
        socket.sethostname(value.encode("ascii"))

    probe = firstboot.kernel_random_bytes(16)
    checks["kernel_entropy"] = isinstance(probe, bytes) and len(probe) == 16
    del probe
    results, applied = [], []
    for root in roots:
        result = firstboot.initialize_system(root, entropy=firstboot.kernel_random_bytes,
                                             set_runtime_hostname=runtime_hostname, owner_uid=0)
        results.append(result)
        applied.append(result["created"] and socket.gethostname() == result["hostname"])
    checks["runtime_hostname_applied"] = all(applied)
    checks["two_distinct_identities"] = results[0]["hostname"] != results[1]["hostname"]

    def no_entropy(_size):
        raise RuntimeError("Existing identity must not request new entropy")

    repeated, permissions, reconciled = [], [], []
    for root, initial in zip(roots, results):
        paths = [root / name for name in ("etc/hostname", "etc/hosts", "var/lib/inkyos/system.json")]
        before = [(path.stat().st_ino, path.read_bytes()) for path in paths]
        result = firstboot.initialize_system(root, entropy=no_entropy,
                                             set_runtime_hostname=runtime_hostname, owner_uid=0)
        repeated.append(not result["created"] and result["hostname"] == initial["hostname"]
                        and socket.gethostname() == result["hostname"]
                        and before == [(path.stat().st_ino, path.read_bytes()) for path in paths])
        for relative, mode in (("var/lib/inkyos", 0o700), ("var/lib/inkyos/system.json", 0o600),
                               ("var/lib/inkyos/.firstboot.lock", 0o600),
                               ("etc/hostname", 0o644), ("etc/hosts", 0o644)):
            metadata = (root / relative).lstat()
            permissions.append(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == mode)
        stored = json.loads((root / "var/lib/inkyos/system.json").read_text())
        hostlines = [(line.split()[:2]) for line in (root / "etc/hosts").read_text().splitlines()
                     if line.split()[:1] == ["127.0.1.1"]]
        reconciled.append(stored["hostname"] == initial["hostname"]
                          and (root / "etc/hostname").read_text() == initial["hostname"] + "\n"
                          and hostlines == [["127.0.1.1", initial["hostname"]]])
    checks["repeat_stable_without_entropy"] = all(repeated)
    checks["private_permissions"] = all(permissions)
    checks["fixture_files_reconciled"] = all(reconciled)
    checks["machine_id_unchanged"] = all((root / "etc/machine-id").read_text() == sentinel for root in roots)
except Exception:
    # Do not echo exception text, hostnames, identifiers or fixture state.
    pass
print(json.dumps(checks, sort_keys=True))
sys.exit(0 if all(checks.values()) else 1)
'''

checks = {"linux_arm64_builder": True, "private_uts_namespace": False,
          "kernel_entropy": False, "runtime_hostname_applied": False,
          "two_distinct_identities": False, "repeat_stable_without_entropy": False,
          "private_permissions": False, "machine_id_unchanged": False,
          "fixture_files_reconciled": False, "child_completed": False,
          "parent_hostname_unchanged": False, "parent_namespace_unchanged": False,
          "fixtures_removed": False}
parent_hostname = socket.gethostname()
parent_uts = os.readlink("/proc/self/ns/uts")
scratch_path = None

def interrupted(_signal, _frame):
    raise InterruptedError("Smoke test interrupted")

signal.signal(signal.SIGTERM, interrupted)
try:
    with tempfile.TemporaryDirectory(prefix="inkyos-firstboot-smoke-", dir="/tmp") as scratch:
        scratch_path = Path(scratch)
        # No --fork: unshare execs the child, so subprocess timeout kills the
        # actual Python worker before the parent removes its fixture directory.
        child = subprocess.run(["unshare", "--uts", sys.executable, "-B", "-",
                                str(Path(sys.argv[1]).resolve()), scratch, parent_uts],
                               input=CHILD, text=True, capture_output=True, timeout=60)
        report = json.loads(child.stdout)
        expected = set(checks) - {"linux_arm64_builder", "child_completed", "parent_hostname_unchanged",
                                  "parent_namespace_unchanged", "fixtures_removed"}
        if isinstance(report, dict) and set(report) == expected and all(type(value) is bool for value in report.values()):
            checks.update(report)
            checks["child_completed"] = child.returncode == 0
except (Exception, KeyboardInterrupt):
    # Captured child output and exceptions may never disclose an identity.
    pass
finally:
    checks["parent_hostname_unchanged"] = socket.gethostname() == parent_hostname
    checks["parent_namespace_unchanged"] = os.readlink("/proc/self/ns/uts") == parent_uts
    checks["fixtures_removed"] = scratch_path is not None and not scratch_path.exists()
passed = all(checks.values())
print(json.dumps({"checks": checks, "passed": passed}, sort_keys=True))
sys.exit(0 if passed else 1)
PY
