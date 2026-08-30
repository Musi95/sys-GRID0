#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
archive_name="sys-zerotier-dev-transfer-2026-08-29.tgz"
archive_path="$project_dir/$archive_name"
temporary_archive="$(mktemp --suffix=.tgz)"
trap 'rm -f "$temporary_archive"' EXIT

cd "$project_dir/.."

tar -czf "$temporary_archive" \
    --exclude='sys-zerotier/.git' \
    --exclude='sys-zerotier/.agents' \
    --exclude='sys-zerotier/.codex' \
    --exclude='sys-zerotier/.research-splatoon' \
    --exclude='sys-zerotier/.szt-transfer.tgz' \
    --exclude='sys-zerotier/sys-zerotier-dev-transfer-*.tgz' \
    --exclude='sys-zerotier/Atmosphere-libs/.git' \
    --exclude='sys-zerotier/Atmosphere-libs/libstratosphere/build' \
    --exclude='sys-zerotier/Atmosphere-libs/libstratosphere/lib' \
    --exclude='sys-zerotier/Atmosphere-libs/libstratosphere/include/stratosphere.hpp.gch' \
    --exclude='sys-zerotier/ZeroTierOne/.git' \
    --exclude='sys-zerotier/build' \
    --exclude='sys-zerotier/build-ztcore' \
    --exclude='sys-zerotier/build.log' \
    --exclude='sys-zerotier/sys-zerotier.elf' \
    --exclude='sys-zerotier/sys-zerotier.nso' \
    --exclude='sys-zerotier/sys-zerotier.nsp' \
    --exclude='sys-zerotier/sys-zerotier.npdm' \
    --exclude='sys-zerotier/tests/test_vnet' \
    --exclude='sys-zerotier/exefs' \
    --exclude='sys-zerotier/exefs.nsp' \
    --exclude='*.secret' \
    --exclude='*token.secret' \
    sys-zerotier

mv -f "$temporary_archive" "$archive_path"
trap - EXIT
printf '%s\n' "$archive_path"
