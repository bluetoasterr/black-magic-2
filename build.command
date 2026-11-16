#!/bin/zsh
set -euo pipefail
root=${0:A:h}
cd "$root"
archive=$(mktemp "${TMPDIR:-/tmp}/kaihen-source.XXXXXX")
trap 'rm -f "$archive"' EXIT
tar -czf "$archive" app bin
cp launcher.command.in 'mac build.command'
base64 < "$archive" >> 'mac build.command'
chmod +x 'mac build.command'
