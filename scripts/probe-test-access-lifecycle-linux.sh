#!/usr/bin/env bash
# Marked VM only; Python creates/removes its own two nonce-prefixed inert units.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/test-access-lifecycle\.[0-9a-f]{8}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/probe-test-access-lifecycle-linux.sh" ]] || exit 2
exec timeout --signal=TERM 160s python3 -I "$work/probe-test-access-lifecycle.py" --inside "$work"
