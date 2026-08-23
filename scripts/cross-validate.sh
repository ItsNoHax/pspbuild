#!/usr/bin/env bash
#
# Cross-validate this crate's output against an independent implementation.
#
# Builds PPSSPP's own PrxDecrypter (plus libkirk) into a small oracle binary,
# encrypts a module with pspbuild, and checks that the oracle decrypts it
# back to the original bytes.
#
# This matters because pspbuild verifying its own output only proves
# self-consistency. The oracle is third-party code that the PSP emulator
# actually uses to load modules.
#
# Usage: scripts/cross-validate.sh <path-to-ppsspp-source> [module.prx]

set -euo pipefail

PPSSPP="${1:-}"
MODULE="${2:-}"

if [[ -z "$PPSSPP" || ! -d "$PPSSPP/ext/libkirk" ]]; then
    echo "usage: $0 <path-to-ppsspp-source> [module.prx]" >&2
    echo "  needs a PPSSPP checkout containing ext/libkirk and Core/ELF" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Building the oracle from PPSSPP sources"
mkdir -p "$WORK/Common" "$WORK/Core/ELF"
cp -r "$PPSSPP/ext" "$WORK/ext"
cp "$PPSSPP/Core/ELF/PrxDecrypter.cpp" "$PPSSPP/Core/ELF/PrxDecrypter.h" "$WORK/Core/ELF/"

cat > "$WORK/Common/CommonTypes.h" <<'EOF'
#pragma once
#include <cstdint>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
typedef u16 u16_le; typedef u32 u32_le; typedef u64 u64_le;
typedef s16 s16_le; typedef s32 s32_le; typedef s64 s64_le;
EOF
printf '#pragma once\n#include "CommonTypes.h"\n' | tee "$WORK/Common/Common.h" > "$WORK/Common/Swap.h"
cat > "$WORK/Common/Log.h" <<'EOF'
#pragma once
namespace Log { enum Type { Loader }; }
#define INFO_LOG(...) do {} while(0)
#define ERROR_LOG(...) do {} while(0)
#define WARN_LOG(...) do {} while(0)
#define DEBUG_LOG(...) do {} while(0)
EOF

cat > "$WORK/oracle.cpp" <<'EOF'
#include <cstdio>
#include <vector>
#include "Core/ELF/PrxDecrypter.h"
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: oracle in.prx out.bin\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<u8> in(size), out(size + 0x1000, 0);
    if (fread(in.data(), 1, size, f) != (size_t)size) { fclose(f); return 2; }
    fclose(f);
    int res = pspDecryptPRX(in.data(), out.data(), (u32)size);
    if (res <= 0) { printf("DECRYPT_FAILED %d\n", res); return 1; }
    printf("DECRYPT_OK %d\n", res);
    FILE *o = fopen(argv[2], "wb");
    if (o) { fwrite(out.data(), 1, res, o); fclose(o); }
    return 0;
}
EOF

cd "$WORK"
gcc -I. -Iext/libkirk -O2 -w -c ext/libkirk/*.c
g++ -std=c++17 -I. -O2 -w -c Core/ELF/PrxDecrypter.cpp -o PrxDecrypter.o
g++ -std=c++17 -I. -O2 -w -c oracle.cpp -o oracle.o
g++ -o oracle ./*.o

echo "==> Building pspbuild"
cd "$ROOT"
cargo build --release --quiet

# Without a supplied module, synthesise one via the test helper shape.
if [[ -z "$MODULE" ]]; then
    echo "==> No module given; using tests/fixtures/ref_tiny.prx as a decrypt-only check"
    "$WORK/oracle" "$ROOT/tests/fixtures/ref_tiny.prx" "$WORK/ref.out"
    echo "PASS: the oracle decrypts the PSPSDK reference fixture"
    exit 0
fi

echo "==> Encrypting $MODULE"
"$ROOT/target/release/pspbuild" encrypt "$MODULE" -o "$WORK/mine.prx"

echo "==> Decrypting with the oracle"
"$WORK/oracle" "$WORK/mine.prx" "$WORK/mine.payload"

# The payload is gzip if pspbuild chose to compress.
if [[ "$(head -c2 "$WORK/mine.payload" | xxd -p)" == "1f8b" ]]; then
    mv "$WORK/mine.payload" "$WORK/mine.payload.gz"
    gunzip -f "$WORK/mine.payload.gz"
fi

if cmp -s "$WORK/mine.payload" "$MODULE"; then
    in_size=$(stat -c%s "$MODULE")
    out_size=$(stat -c%s "$WORK/mine.prx")
    echo
    echo "PASS: an independent decrypter recovered the module byte for byte"
    printf "  input:  %10d bytes\n" "$in_size"
    printf "  output: %10d bytes\n" "$out_size"
else
    echo "FAIL: recovered payload differs from the original module" >&2
    exit 1
fi
