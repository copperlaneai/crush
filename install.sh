#!/bin/sh

set -eu

repository='copperlaneai/crush'
github_url="https://github.com/${repository}"
version='latest'
default_install_dir=${HOME:+"${HOME}/.local/bin"}
install_dir=$default_install_dir
force=0
modify_path=1

usage() {
    cat <<'EOF'
Install Crisp Remote Uninterrupted Shell from a signed GitHub release.

Usage: install.sh [OPTIONS]

Options:
  --version VERSION  Install an exact version (for example, 0.1.0 or v0.1.0)
  --dir DIRECTORY    Install directory (default: ~/.local/bin)
  --force            Replace an existing non-directory destination named crush
  --no-modify-path   Do not add ~/.local/bin to the shell startup file
  -h, --help         Show this help

The installer verifies the archive with SHA256SUMS. If cosign is available, it
also authenticates SHA256SUMS to copperlaneai/crush's release workflow.
EOF
}

fail() {
    printf 'crush installer: %s\n' "$*" >&2
    exit 1
}

say() {
    printf 'crush installer: %s\n' "$*"
}

need_value() {
    [ "$#" -ge 2 ] || fail "$1 requires a value"
    [ -n "$2" ] || fail "$1 requires a non-empty value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            need_value "$@"
            version=$2
            shift 2
            ;;
        --dir)
            need_value "$@"
            install_dir=$2
            shift 2
            ;;
        --force)
            force=1
            shift
            ;;
        --no-modify-path)
            modify_path=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            [ "$#" -eq 0 ] || fail "unexpected positional argument: $1"
            ;;
        -*)
            fail "unknown option: $1"
            ;;
        *)
            fail "unexpected positional argument: $1"
            ;;
    esac
done

[ -n "${install_dir:-}" ] || fail 'HOME is not set; pass --dir DIRECTORY'

for command_name in awk curl install ln mktemp tar uname; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
done

os=$(uname -s)
architecture=$(uname -m)

case "$architecture" in
    x86_64 | amd64)
        rust_arch='x86_64'
        ;;
    arm64 | aarch64)
        rust_arch='aarch64'
        ;;
    *)
        fail "unsupported architecture: ${architecture}"
        ;;
esac

case "$os" in
    Darwin)
        target="${rust_arch}-apple-darwin"
        ;;
    Linux)
        target="${rust_arch}-unknown-linux-musl"
        ;;
    *)
        fail "unsupported operating system: ${os}"
        ;;
esac

curl_get() {
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --retry-delay 1 --output "$2" "$1"
}

if [ "$version" = 'latest' ]; then
    latest_url=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        --location --head --output /dev/null --write-out '%{url_effective}' \
        "${github_url}/releases/latest")
    latest_tag=${latest_url##*/}
    case "$latest_tag" in
        v*) version=${latest_tag#v} ;;
        *) fail "could not determine latest release from ${latest_url}" ;;
    esac
else
    version=${version#v}
fi

if ! printf '%s\n' "$version" | awk '
    /^[0-9]+\.[0-9]+\.[0-9]+$/ { valid = 1 }
    END { exit valid ? 0 : 1 }
'; then
    fail "invalid version '${version}'; expected MAJOR.MINOR.PATCH"
fi

asset="crush-${version}-${target}.tar.gz"
release_url="${github_url}/releases/download/v${version}"
destination="${install_dir}/crush"

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/crush-install.XXXXXX")
cleanup() {
    rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$install_dir"

if [ -d "$destination" ]; then
    fail "${destination} is a directory; refusing to replace it"
fi

if [ -e "$destination" ] || [ -L "$destination" ]; then
    if [ "$force" -eq 1 ]; then
        say "--force supplied; replacing existing ${destination}"
    else
        fail "${destination} already exists; use --force to replace it"
    fi
fi

archive="${temporary_dir}/${asset}"
checksums="${temporary_dir}/SHA256SUMS"

say "downloading Crush ${version} for ${target}"
curl_get "${release_url}/${asset}" "$archive"
curl_get "${release_url}/SHA256SUMS" "$checksums"

if command -v cosign >/dev/null 2>&1; then
    checksum_bundle="${temporary_dir}/SHA256SUMS.sigstore.json"
    curl_get "${release_url}/SHA256SUMS.sigstore.json" "$checksum_bundle"
    if ! cosign verify-blob \
        --bundle "$checksum_bundle" \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --certificate-identity-regexp \
        '^https://github.com/copperlaneai/crush/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
        "$checksums" >/dev/null 2>&1; then
        fail 'Sigstore verification of SHA256SUMS failed'
    fi
    say 'verified release identity with Sigstore'
else
    say 'cosign not found; continuing with SHA-256 verification only'
fi

checksum_matches=$(awk -v asset="$asset" '
    $2 == asset && length($1) == 64 { count += 1 }
    END { print count + 0 }
' "$checksums")
[ "$checksum_matches" -ne 0 ] || fail "${asset} is missing from SHA256SUMS"
[ "$checksum_matches" -eq 1 ] || fail "SHA256SUMS contains duplicate entries for ${asset}"

expected_hash=$(awk -v asset="$asset" '
    $2 == asset && length($1) == 64 { print tolower($1); exit }
' "$checksums")

if command -v sha256sum >/dev/null 2>&1; then
    actual_hash=$(sha256sum "$archive" | awk '{ print tolower($1) }')
elif command -v shasum >/dev/null 2>&1; then
    actual_hash=$(shasum -a 256 "$archive" | awk '{ print tolower($1) }')
else
    fail 'neither sha256sum nor shasum is available'
fi

[ "$actual_hash" = "$expected_hash" ] || fail "SHA-256 mismatch for ${asset}"

archive_list="${temporary_dir}/archive-list"
tar -tzf "$archive" >"$archive_list" || fail "could not inspect ${asset}"

if awk '
    /^\// || /(^|\/)\.\.($|\/)/ || /\\/ { unsafe = 1 }
    END { exit unsafe ? 0 : 1 }
' "$archive_list"; then
    fail "${asset} contains an unsafe path"
fi

for required_entry in crush README.md LICENSE-MIT LICENSE-APACHE; do
    if ! awk -v required="$required_entry" '$0 == required { found = 1 } END { exit found ? 0 : 1 }' \
        "$archive_list"; then
        fail "${asset} is missing ${required_entry}"
    fi
done

if awk '
    $0 != "crush" && $0 != "README.md" && $0 != "LICENSE-MIT" && $0 != "LICENSE-APACHE" {
        unexpected = 1
    }
    END { exit unexpected ? 0 : 1 }
' "$archive_list"; then
    fail "${asset} contains unexpected files"
fi

unpack_dir="${temporary_dir}/unpack"
mkdir "$unpack_dir"
tar -xzf "$archive" -C "$unpack_dir"

if [ ! -f "${unpack_dir}/crush" ] || [ -L "${unpack_dir}/crush" ]; then
    fail 'archive does not contain a regular crush executable'
fi
chmod 0755 "${unpack_dir}/crush"

installed_version=$(
    unset CRUSH_SSH CRUSH_MODE CRUSH_PREDICT CRUSH_TRACE
    CRUSH_ACTION=version "${unpack_dir}/crush" </dev/null 2>/dev/null
) || \
    fail 'downloaded crush executable failed its version check'
[ "$installed_version" = "crush ${version}" ] || \
    fail "downloaded executable reported an unexpected version: ${installed_version}"

staged_path=$(mktemp "${install_dir}/.crush.XXXXXX")
install -m 0755 "${unpack_dir}/crush" "$staged_path"
if [ "$force" -eq 1 ]; then
    mv -f "$staged_path" "$destination"
elif ! ln "$staged_path" "$destination"; then
    rm -f "$staged_path"
    fail "${destination} already exists; use --force to replace it"
else
    rm -f "$staged_path"
fi

say "installed ${destination}"
case ":${PATH:-}:" in
    *:"$install_dir":*) ;;
    *)
        path_profile=''
        path_line=''
        if [ "$modify_path" -eq 1 ] && [ "$install_dir" = "$default_install_dir" ]; then
            shell_name=${SHELL##*/}
            case "$shell_name" in
                zsh)
                    path_profile="${ZDOTDIR:-$HOME}/.zshrc"
                    path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
                    ;;
                bash)
                    if [ "$os" = 'Darwin' ]; then
                        path_profile="${HOME}/.bash_profile"
                    else
                        path_profile="${HOME}/.bashrc"
                    fi
                    path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
                    ;;
                fish)
                    path_profile="${HOME}/.config/fish/config.fish"
                    path_line="fish_add_path \"\$HOME/.local/bin\""
                    ;;
                *)
                    path_profile="${HOME}/.profile"
                    path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
                    ;;
            esac

            profile_directory=${path_profile%/*}
            if mkdir -p "$profile_directory" &&
                { [ ! -e "$path_profile" ] || [ -f "$path_profile" ]; } &&
                ! awk -v line="$path_line" '$0 == line { found = 1 } END { exit found ? 0 : 1 }' \
                    "$path_profile" 2>/dev/null; then
                if [ -s "$path_profile" ]; then
                    path_prefix='\n'
                else
                    path_prefix=''
                fi
                if printf '%b%s\n' "$path_prefix" "$path_line" >>"$path_profile"; then
                    say "added ${install_dir} to PATH in ${path_profile}"
                fi
            fi
        fi

        say "restart your shell or add ${install_dir} to PATH to invoke crush directly"
        ;;
esac
