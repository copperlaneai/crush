#!/bin/sh

set -eu

usage() {
    printf 'usage: %s VERSION TARGET BINARY OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
}

[ "$#" -eq 4 ] || usage

version=$1
target=$2
binary=$3
output_directory=$4

if ! printf '%s\n' "$version" | awk '
    /^[0-9]+\.[0-9]+\.[0-9]+$/ { valid = 1 }
    END { exit valid ? 0 : 1 }
'; then
    printf 'package-release: invalid version: %s\n' "$version" >&2
    exit 2
fi

case "$target" in
    aarch64-apple-darwin | \
    aarch64-unknown-linux-gnu | \
    aarch64-unknown-linux-musl | \
    x86_64-apple-darwin | \
    x86_64-unknown-linux-gnu | \
    x86_64-unknown-linux-musl)
        ;;
    *)
        printf 'package-release: unsupported target: %s\n' "$target" >&2
        exit 2
        ;;
esac

[ -f "$binary" ] || {
    printf 'package-release: binary not found: %s\n' "$binary" >&2
    exit 1
}

binary_size=$(wc -c <"$binary" | tr -d '[:space:]')
[ "$binary_size" -le 5242880 ] || {
    printf 'package-release: binary is %s bytes; release gate is 5242880\n' "$binary_size" >&2
    exit 1
}

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
mkdir -p "$output_directory"
output_directory=$(CDPATH='' cd -- "$output_directory" && pwd -P)

staging_directory=$(mktemp -d "${TMPDIR:-/tmp}/crush-package.XXXXXX")
cleanup() {
    rm -rf "$staging_directory"
}
trap cleanup EXIT HUP INT TERM

install -m 0755 "$binary" "${staging_directory}/crush"
install -m 0644 "${repository_root}/README.md" "${staging_directory}/README.md"
install -m 0644 "${repository_root}/LICENSE" "${staging_directory}/LICENSE"

archive="${output_directory}/crush-${version}-${target}.tar.gz"
(
    cd "$staging_directory"
    COPYFILE_DISABLE=1 tar -czf "$archive" crush README.md LICENSE
)

printf '%s\n' "$archive"
