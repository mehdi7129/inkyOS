#!/usr/bin/env bash
# Disposable parent copy only; private PID/net/mount/UTS, no host service/socket/radio.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/test-access-network\.[0-9a-f]{8}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/probe-test-access-network-linux.sh" ]] || exit 2
if [[ ${INKYOS_TEST_NETWORK_NAMESPACE:-} != 1 ]]; then
  exec timeout --signal=TERM --kill-after=30s 180s \
    unshare --mount --net --uts --pid --fork --kill-child=KILL --propagation private \
    env INKYOS_TEST_NETWORK_NAMESPACE=1 bash "$0" "$work"
fi
for namespace in mnt net uts pid; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
exec python3 -I "$work/probe-test-access-network.py" --inside "$work"
