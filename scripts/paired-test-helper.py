#!/usr/bin/env python3
"""Helper for scripts/paired-test.local.sh: config.toml scoping and folder-id
resolution. Deployed to the peer host by the shell script; not shipped
anywhere, not part of the l2sync binary.

Usage:
  paired-test-helper.py scope <config.toml> <keep-peer> <keep-folder>
  paired-test-helper.py resolve-id <config.toml> <folder-name>
"""
import re
import sys


def scope(path, keep_peer, keep_folder):
    lines = open(path).read().splitlines()
    out = []
    mode = "keep"
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1]
            if name in ("peers", "shared", "remote"):
                mode = "keep"
                out.append(line)
                continue
            top, _, sub = name.partition(".")
            if top == "peers":
                mode = "keep" if sub == keep_peer else "skip"
            elif top in ("shared", "remote"):
                mode = "keep" if sub == keep_folder else "skip"
            else:
                mode = "keep"
            if mode == "keep":
                out.append(line)
            continue
        if mode != "skip":
            out.append(line)
    open(path, "w").write("\n".join(out) + "\n")


def resolve_id(config_path, folder):
    text = open(config_path).read()
    match = re.search(r'^\[(?:shared|remote)\.' + re.escape(folder) + r'\]\npath = "([^"]+)"', text, re.MULTILINE)
    if not match:
        sys.exit(f"folder {folder!r} not found in {config_path}")
    marker_path = match.group(1) + "/.l2sync"
    marker_text = open(marker_path).read()
    id_match = re.search(r'^id\s*=\s*"([^"]+)"', marker_text, re.MULTILINE)
    if not id_match:
        sys.exit(f"no id found in {marker_path}")
    print(id_match.group(1))


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "scope":
        scope(sys.argv[2], sys.argv[3], sys.argv[4])
    elif command == "resolve-id":
        resolve_id(sys.argv[2], sys.argv[3])
    else:
        sys.exit(f"unknown command {command!r}")
