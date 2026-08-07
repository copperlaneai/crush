#!/bin/sh

set -eu

usage() {
    printf 'usage: %s VERSION DISTRIBUTION_DIRECTORY\n' "$0" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage

version=$1
distribution_directory=$2

if ! printf '%s\n' "$version" | awk '
    /^[0-9]+\.[0-9]+\.[0-9]+$/ { valid = 1 }
    END { exit valid ? 0 : 1 }
'; then
    printf 'prepare-release-assets: invalid version: %s\n' "$version" >&2
    exit 2
fi

[ -d "$distribution_directory" ] || {
    printf 'prepare-release-assets: directory not found: %s\n' "$distribution_directory" >&2
    exit 1
}

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
distribution_directory=$(CDPATH='' cd -- "$distribution_directory" && pwd -P)

for target in \
    aarch64-apple-darwin \
    aarch64-unknown-linux-gnu \
    aarch64-unknown-linux-musl \
    x86_64-apple-darwin \
    x86_64-unknown-linux-gnu \
    x86_64-unknown-linux-musl; do
    asset="${distribution_directory}/crush-${version}-${target}.tar.gz"
    [ -f "$asset" ] || {
        printf 'prepare-release-assets: release archive not found: %s\n' "$asset" >&2
        exit 1
    }
done

archive_count=0
for archive in "$distribution_directory"/*.tar.gz; do
    [ -f "$archive" ] || continue
    archive_count=$((archive_count + 1))
done
[ "$archive_count" -eq 6 ] || {
    printf 'prepare-release-assets: expected 6 archives, found %s\n' "$archive_count" >&2
    exit 1
}

install -m 0755 "${repository_root}/install.sh" \
    "${distribution_directory}/crush-installer.sh"

(
    cd "$distribution_directory"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- crush-installer.sh crush-"${version}"-*.tar.gz >SHA256SUMS
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 crush-installer.sh crush-"${version}"-*.tar.gz >SHA256SUMS
    else
        printf 'prepare-release-assets: neither sha256sum nor shasum is available\n' >&2
        exit 1
    fi
)
