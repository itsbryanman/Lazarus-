#!/usr/bin/env bash
set -euo pipefail

ALPINE_URL=${ALPINE_URL:-"https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.2-x86_64.iso"}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
WORKSPACE_ROOT=$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)
OUTPUT_ISO=${1:-"${WORKSPACE_ROOT}/lazarus-recovery.iso"}
RECOVERY_BIN=${2:-"${WORKSPACE_ROOT}/target/release/lazarus-recovery"}

for dep in curl xorriso bsdtar; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "Missing dependency: $dep" >&2
        exit 1
    fi
done

if [[ ! -x "$RECOVERY_BIN" ]]; then
    echo "Recovery binary not found at $RECOVERY_BIN" >&2
    echo "Build it first, e.g. 'cargo build --release -p lazarus-recovery'" >&2
    exit 1
fi

WORKDIR=$(mktemp -d)
ISO_PATH="$WORKDIR/alpine.iso"
EXTRACT_DIR="$WORKDIR/alpine"
mkdir -p "$EXTRACT_DIR"

trap 'rm -rf "$WORKDIR"' EXIT

echo "Downloading Alpine ISO..."
curl -L "$ALPINE_URL" -o "$ISO_PATH"

echo "Extracting ISO contents..."
xorriso -osirrox on -indev "$ISO_PATH" -extract / "$EXTRACT_DIR" >/dev/null

install -Dm755 "$RECOVERY_BIN" "$EXTRACT_DIR/usr/bin/lazarus"
cat <<'RC' > "$EXTRACT_DIR/etc/profile.d/lazarus.sh"
#!/bin/sh
if [ -z "$DISPLAY" ] && [ -t 0 ]; then
    /usr/bin/lazarus
fi
RC
chmod +x "$EXTRACT_DIR/etc/profile.d/lazarus.sh"

if [[ -f "$EXTRACT_DIR/root/.profile" ]]; then
    if ! grep -q '/usr/bin/lazarus' "$EXTRACT_DIR/root/.profile"; then
        printf '\n/usr/bin/lazarus\n' >> "$EXTRACT_DIR/root/.profile"
    fi
fi

echo "Repacking ISO to $OUTPUT_ISO ..."
xorriso \
    -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "LAZARUS_RECOVERY" \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -o "$OUTPUT_ISO" \
    "$EXTRACT_DIR" >/dev/null

echo "Recovery ISO written to $OUTPUT_ISO"
