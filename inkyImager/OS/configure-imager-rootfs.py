#!/usr/bin/env python3
"""Install the small, normal-LAN imager boot profile into an offline image.

Call only after configure-rootfs.configure(..., factory=None) and the reviewed
Studio bundle materializer. This deliberately refuses an active factory image.
It never edits the backend, executes target programs or seeds personal data.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat


FORBIDDEN = (
    "etc/inky-studio/factory-v1.json", "etc/inkyos/factory-runtime-v1.json",
    "run/inkyos-factory", "var/lib/inkyos-factory",
    "var/lib/inkyos/factory-permission.json", "etc/inkyos-test-enrollment",
    "var/lib/inkyos-test-access", "usr/lib/inkyos/factory-main.py",
    "usr/lib/systemd/system/inkyos-factory-start.service",
    "etc/systemd/system/multi-user.target.wants/inkyos-factory-start.service",
    "etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf",
    "etc/systemd/system/NetworkManager.service.d/20-inkyos-wlan-close.conf",
    "usr/lib/systemd/system/inkyos-wlan-close.service",
)


def load_tree(recipe):
    path = Path(recipe) / "scripts/configure-rootfs.py"
    spec = importlib.util.spec_from_file_location("imager_static_tree", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Tree


def render_environment(values):
    if type(values) is not dict or not values:
        raise ValueError("A reviewed nonempty backend environment is required")
    lines = []
    for key, value in sorted(values.items()):
        if (type(key) is not str or not re.fullmatch(r"INKY_STUDIO_[A-Z0-9_]+", key)
                or "FACTORY" in key or "BLUETOOTH" in key or "SOFTAP" in key
                or type(value) is not str or not value or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ValueError("Invalid normal-LAN backend environment")
        lines.append(key + '="' + value.replace("\\", "\\\\").replace('"', '\\"') + '"')
    return "\n".join(lines) + "\n"


def configure(rootfs, bootfs, recipe, source, *, backend_exec_start, backend_environment):
    root, boot, source = Path(rootfs), Path(bootfs), Path(source)
    if any(path == Path("/") or path.is_symlink() or not path.is_dir() for path in (root, boot)):
        raise ValueError("An ordinary offline rootfs is required")
    if os.path.lexists(boot / "inky-imager.json"):
        raise ValueError("A distributed image must not contain personal Wi-Fi data")
    if any(os.path.lexists(root / path) for path in FORBIDDEN):
        raise ValueError("Factory/test image refused; start from the pristine normal profile")
    if (not re.fullmatch(r"/usr/lib/inky-studio/server/\.venv/bin/python3(?:\.13)? -I -B -m inky_web\.[a-z_]+",
                         backend_exec_start)):
        raise ValueError("The reviewed normal-LAN Python entrypoint is required")
    Tree = load_tree(recipe)
    tree = Tree(root)
    boot_tree = Tree(boot)
    network_state = tree.read("var/lib/NetworkManager/NetworkManager.state")
    if not network_state or "WirelessEnabled=true" not in network_state or "WirelessEnabled=false" in network_state:
        raise ValueError("configure-rootfs(factory=None) must run first")
    # A distributed image must contain neither a Wi-Fi capsule nor a committed
    # personal profile/state. The Mac app supplies the capsule to its private RAW.
    for path in ("etc/NetworkManager/system-connections/inky-home.nmconnection",
                 "var/lib/inkyos/imager-network.json"):
        if os.path.lexists(root / path):
            raise ValueError("Image already contains imager network state")
    copied = {
        "usr/local/lib/inkyos/imager-firstboot.py": ("imager-firstboot.py", 0o555),
        "etc/systemd/system/inkyos-imager-firstboot.service": ("inkyos-imager-firstboot.service", 0o644),
        "etc/systemd/system/NetworkManager.service.d/20-inky-imager-wifi.conf": ("20-inky-imager-wifi.conf", 0o644),
    }
    for target, (name, mode) in copied.items():
        path = source / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("An ordinary reviewed source file is required")
        tree.write(target, path.read_text(), mode)
    unit = (source / "inky-studio.service.in").read_text()
    if unit.count("@BACKEND_EXEC_START@") != 1:
        raise ValueError("The normal-LAN unit template changed")
    unit = unit.replace("@BACKEND_EXEC_START@", backend_exec_start)
    if "@BACKEND_" in unit:
        raise ValueError("Unbound backend unit template")
    tree.write("usr/lib/systemd/system/inky-studio.service", unit, 0o644)
    tree.write("etc/inky-studio/imager.env", render_environment(backend_environment), 0o600)
    # The boot volume contains a transient Wi-Fi capsule on the user's card.
    # Keep it out of Spotlight indexing and its post-flash volume handles.
    boot_tree.write(".metadata_never_index", "", 0o644)
    # No saved soft-block is allowed to race the importer's explicit WLAN
    # activation. Bluetooth is not part of this installation method.
    for name in ("systemd-rfkill.service", "systemd-rfkill.socket", "bluetooth.service"):
        tree.link("etc/systemd/system/" + name, "/dev/null")
    tree.link("etc/systemd/system/inky-studio.service", "/usr/lib/systemd/system/inky-studio.service")
    for name in ("inkyos-imager-firstboot.service", "inky-studio.service"):
        tree.link("etc/systemd/system/multi-user.target.wants/" + name,
                  "/etc/systemd/system/" + name)
    return {"kind": "imager-normal-lan-profile", "wifi_preconfigured": False,
            "factory_runtime": False, "bluetooth": False, "services_enabled": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--bootfs", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).parent)
    parser.add_argument("--backend-exec-start", required=True)
    parser.add_argument("--backend-env-json", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not os.sys.platform.startswith("linux"):
        parser.error("Use the isolated Linux image builder")
    import json
    result = configure(args.rootfs, args.bootfs, args.recipe, args.source,
                       backend_exec_start=args.backend_exec_start,
                       backend_environment=json.loads(args.backend_env_json.read_text()))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
