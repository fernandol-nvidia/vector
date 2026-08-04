#!/usr/bin/env bash
# Package one Tribe Vector binary into an upstream-shaped tar.gz archive.
# Usage: package-archive.sh <vector-binary> <version> <target-triple> <output-dir>
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <absolute-vector-binary> <version> <target-triple> <absolute-output-dir>" >&2
  exit 2
fi

vector_binary=$1
version=$2
triple=$3
output_dir=$4
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_root/../.." && pwd)

if [[ $vector_binary != /* || $output_dir != /* ]]; then
  echo "vector binary and output directory must be absolute" >&2
  exit 2
fi
if [[ ! -f $vector_binary || -L $vector_binary || ! -x $vector_binary ]]; then
  echo "vector binary must be an executable regular file" >&2
  exit 2
fi
if [[ -z $version || -z $triple ]]; then
  echo "version and target triple are required" >&2
  exit 2
fi

archive_root=$output_dir/vector-$version-$triple
archive_name=vector-$version-$triple.tar.gz
rm -rf "$archive_root"
mkdir -p "$archive_root/bin" "$archive_root/config" "$archive_root/licenses"

install -m 0755 "$vector_binary" "$archive_root/bin/vector"
install -m 0644 "$repo_root/LICENSE" "$archive_root/LICENSE"
if [[ -f $repo_root/README.md ]]; then
  install -m 0644 "$repo_root/README.md" "$archive_root/README.md"
fi
: >"$archive_root/licenses/.keep"
printf '%s\n' \
  "# Tribe Vector closed-feature package" \
  "# Features: api,sources-http_server,transforms-remap,transforms-filter,sinks-http" \
  >"$archive_root/config/README.md"

mkdir -p "$output_dir"
tar -C "$output_dir" -czf "$output_dir/$archive_name" "vector-$version-$triple"
rm -rf "$archive_root"

(
  cd "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive_name" >"vector-$version-$triple.sha256"
  else
    shasum -a 256 "$archive_name" >"vector-$version-$triple.sha256"
  fi
)

printf '%s\n' "$output_dir/$archive_name"
