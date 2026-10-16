#!/bin/sh
# Cross-build existing byte-level regression tests, using release CPU/ABI flags.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ZIG=${ZIG:-zig}
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
OUT="$ROOT/build/telegram"
mkdir -p "$OUT"
for ARCH in $ARCHES; do
    . "$ROOT/scripts/build-target.sh"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/core/test_crypto.c" "$ROOT/core/crypto.c" -o "$OUT/crypto-$ARCH"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/core/test_quicwire.c" "$ROOT/core/quicwire.c" "$ROOT/core/crypto.c" \
        -o "$OUT/quicwire-$ARCH"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/datapath/test_plan_parse.c" "$ROOT/datapath/plan_parse.c" \
        -o "$OUT/plan-parse-$ARCH"
    prefix="$ROOT/build/telegram/openssl-$ARCH"
    libdir="$prefix/lib"
    [ -d "$libdir" ] || libdir="$prefix/lib64"
    # Cross-compile the C11 MTProto crypto vectors against the target OpenSSL.
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c11 \
        -I"$ROOT/telegram/include" -I"$prefix/include" \
        "$ROOT/telegram/test_mtproto.c" "$ROOT/telegram/src/mtproto_crypto.c" \
        -L"$libdir" -lssl -lcrypto -ldl -pthread -o "$OUT/tg-mtproto-$ARCH"
done
