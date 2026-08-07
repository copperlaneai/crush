#!/bin/sh

set -eu

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/crush-installer-test.XXXXXX")
cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

assets="${test_root}/assets"
mock_bin="${test_root}/bin"
destination_dir="${test_root}/destination"
mkdir -p "$assets" "$mock_bin" "$destination_dir"

cat >"${test_root}/crush" <<'EOF'
#!/bin/sh
if [ "${CRUSH_ACTION:-}" = version ]; then
    printf 'crush 9.8.7\n'
    exit 0
fi
printf 'fixture crush\n'
EOF
chmod 0755 "${test_root}/crush"

"${repository_root}/scripts/package-release.sh" \
    9.8.7 \
    x86_64-unknown-linux-musl \
    "${test_root}/crush" \
    "$assets" >/dev/null

(
    cd "$assets"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum crush-9.8.7-x86_64-unknown-linux-musl.tar.gz >SHA256SUMS
    else
        shasum -a 256 crush-9.8.7-x86_64-unknown-linux-musl.tar.gz >SHA256SUMS
    fi
)

cat >"${mock_bin}/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
    -s) printf 'Linux\n' ;;
    -m) printf 'x86_64\n' ;;
    *) exit 2 ;;
esac
EOF

cat >"${mock_bin}/curl" <<'EOF'
#!/bin/sh
set -eu

output=''
url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            output=$2
            shift 2
            ;;
        --retry | --retry-delay | --write-out)
            shift 2
            ;;
        http://* | https://*)
            url=$1
            shift
            ;;
        *)
            shift
            ;;
    esac
done

[ -n "$output" ] && [ -n "$url" ] || exit 2
asset=${url##*/}
case "$asset" in
    crush-9.8.7-x86_64-unknown-linux-musl.tar.gz | SHA256SUMS)
        cp "${CRUSH_TEST_ASSETS}/${asset}" "$output"
        ;;
    *)
        printf 'unexpected mock download: %s\n' "$url" >&2
        exit 2
        ;;
esac
EOF

chmod 0755 "${mock_bin}/curl" "${mock_bin}/uname"

test_path="${mock_bin}:/usr/bin:/bin"

CRUSH_TEST_ASSETS=$assets PATH=$test_path sh "${repository_root}/install.sh" \
    --version 9.8.7 --dir "$destination_dir" >/dev/null
test "$(CRUSH_ACTION=version "${destination_dir}/crush")" = 'crush 9.8.7'

if CRUSH_TEST_ASSETS=$assets PATH=$test_path sh "${repository_root}/install.sh" \
    --version 9.8.7 --dir "$destination_dir" >/dev/null 2>&1; then
    printf 'installer replaced an existing Crush installation without --force\n' >&2
    exit 1
fi

execution_marker="${test_root}/preexisting-binary-was-executed"
cat >"${destination_dir}/crush" <<'EOF'
#!/bin/sh
: >"${CRUSH_TEST_EXECUTION_MARKER:?}"
printf 'crush 9.8.7\n'
EOF
chmod 0755 "${destination_dir}/crush"

if CRUSH_TEST_EXECUTION_MARKER=$execution_marker CRUSH_TEST_ASSETS=$assets PATH=$test_path \
    sh "${repository_root}/install.sh" --version 9.8.7 --dir "$destination_dir" \
    >/dev/null 2>&1; then
    printf 'installer replaced a recognizable existing executable without --force\n' >&2
    exit 1
fi
if [ -e "$execution_marker" ]; then
    printf 'installer executed the preexisting destination during collision handling\n' >&2
    exit 1
fi

cat >"${destination_dir}/crush" <<'EOF'
#!/bin/sh
printf 'unrelated program\n'
EOF
chmod 0755 "${destination_dir}/crush"

if CRUSH_TEST_ASSETS=$assets PATH=$test_path sh "${repository_root}/install.sh" \
    --version 9.8.7 --dir "$destination_dir" >/dev/null 2>&1; then
    printf 'installer replaced an unrelated executable without --force\n' >&2
    exit 1
fi
test "$("${destination_dir}/crush")" = 'unrelated program'

CRUSH_TEST_ASSETS=$assets PATH=$test_path sh "${repository_root}/install.sh" \
    --version 9.8.7 --dir "$destination_dir" --force >/dev/null
test "$(CRUSH_ACTION=version "${destination_dir}/crush")" = 'crush 9.8.7'

profile_home="${test_root}/profile-home"
mkdir -p "$profile_home"
HOME=$profile_home ZDOTDIR='' SHELL=/bin/zsh CRUSH_TEST_ASSETS=$assets PATH=$test_path \
    sh "${repository_root}/install.sh" --version 9.8.7 >/dev/null
test "$(CRUSH_ACTION=version "${profile_home}/.local/bin/crush")" = 'crush 9.8.7'
test "$(tail -n 1 "${profile_home}/.zshrc")" = \
    "export PATH=\"\$HOME/.local/bin:\$PATH\""
HOME=$profile_home ZDOTDIR='' SHELL=/bin/zsh CRUSH_TEST_ASSETS=$assets PATH=$test_path \
    sh "${repository_root}/install.sh" --version 9.8.7 --force >/dev/null
test "$(awk '/^export PATH=/ { count += 1 } END { print count + 0 }' \
    "${profile_home}/.zshrc")" -eq 1

no_path_home="${test_root}/no-path-home"
mkdir -p "$no_path_home"
HOME=$no_path_home ZDOTDIR='' SHELL=/bin/zsh CRUSH_TEST_ASSETS=$assets PATH=$test_path \
    sh "${repository_root}/install.sh" --version 9.8.7 --no-modify-path >/dev/null
test ! -e "${no_path_home}/.zshrc"

pipe_home="${test_root}/pipe-home"
pipe_destination="${pipe_home}/bin"
mkdir -p "$pipe_destination"
HOME=$pipe_home CRUSH_TEST_ASSETS=$assets PATH=$test_path \
    sh -s -- --version 9.8.7 --dir "$pipe_destination" \
    <"${repository_root}/install.sh" >/dev/null
test "$(CRUSH_ACTION=version "${pipe_destination}/crush")" = 'crush 9.8.7'

printf 'installer tests passed\n'
