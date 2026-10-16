#!/bin/sh
set -eu

# OpenSSL source is fetched at an immutable upstream commit, then built into a
# static musl archive for the selected router architecture.
OPENSSL_COMMIT=f4dc4d58b48d346a8270183f89acf826d459b0ca
ZLIB_COMMIT=51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/build-target.sh"
ZIG=$BUILD_ZIG
JOBS=${JOBS:-4}
SRC_DIR=${OPENSSL_SRC_DIR:-"$ROOT/build/telegram/openssl-src"}
PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-$ARCH"}
OBJ_DIR=${OPENSSL_OBJ_DIR:-"$ROOT/build/telegram/obj-$ARCH"}
ZLIB_SRC_DIR=${ZLIB_SRC_DIR:-"$ROOT/build/telegram/zlib-src"}
ZLIB_PREFIX=${ZLIB_PREFIX:-"$ROOT/build/telegram/zlib-$ARCH"}
ZLIB_OBJ_DIR=${ZLIB_OBJ_DIR:-"$ROOT/build/telegram/zlib-obj-$ARCH"}
OUT=${OUT:-"$ROOT/builds"}

command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found: $ZIG" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required to fetch pinned OpenSSL" >&2; exit 1; }
mkdir -p "$(dirname -- "$SRC_DIR")" "$PREFIX"
mkdir -p "$ROOT/build/telegram" "$OBJ_DIR" "$ZLIB_PREFIX" "$ZLIB_OBJ_DIR" "$OUT"

if [ ! -d "$ZLIB_SRC_DIR/.git" ]; then
    git init "$ZLIB_SRC_DIR"
    git -C "$ZLIB_SRC_DIR" remote add origin https://github.com/madler/zlib.git
fi
zlib_actual=$(git -C "$ZLIB_SRC_DIR" rev-parse HEAD 2>/dev/null || true)
if [ "$zlib_actual" != "$ZLIB_COMMIT" ]; then
    git -C "$ZLIB_SRC_DIR" fetch --depth 1 origin "$ZLIB_COMMIT"
    git -C "$ZLIB_SRC_DIR" checkout --detach "$ZLIB_COMMIT"
fi
[ "$(git -C "$ZLIB_SRC_DIR" rev-parse HEAD)" = "$ZLIB_COMMIT" ] || {
    echo "zlib source revision mismatch" >&2
    exit 1
}

cd "$ZLIB_OBJ_DIR"
# zlib нужен только для bounded распаковки gzip_packed help.getConfig.
CHOST="$TARGET" CC="$ZIG cc -target $TARGET $TARGET_FLAGS $SIZE_CFLAGS" \
AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    CFLAGS="-O2 -fPIC $SIZE_CFLAGS" \
    "$ZLIB_SRC_DIR/configure" --static --prefix="$ZLIB_PREFIX"
make -j "$JOBS"
make install

if [ ! -d "$SRC_DIR/.git" ]; then
    git init "$SRC_DIR"
    git -C "$SRC_DIR" remote add origin https://github.com/openssl/openssl.git
fi
actual=$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || true)
if [ "$actual" != "$OPENSSL_COMMIT" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$OPENSSL_COMMIT"
    git -C "$SRC_DIR" checkout --detach "$OPENSSL_COMMIT"
fi
[ "$(git -C "$SRC_DIR" rev-parse HEAD)" = "$OPENSSL_COMMIT" ] || {
    echo "OpenSSL source revision mismatch" >&2
    exit 1
}

cd "$OBJ_DIR"
# Размер d2ktg важен для роутеров с 8/16 МиБ флеша. Секции функций и данных
# вместе с --gc-sections позволяют линкеру убрать неиспользуемый код.
# Локальному runtime нужны TLS-клиент и проверка X.509/hostname, SHA-1,
# SHA-256, AES-256, RAND и операции OpenSSL BIGNUM для MTProto.
# Не отключать эти возможности ради размера. UNUSED_FEATURES ниже отключает
# только неиспользуемые протоколы и алгоритмы; TLS, RSA и EC остаются доступны.
# Замер 12.10.2026 (предыдущая версия d2ktg), big-endian mips:
# 5 953 012 -> 5 187 940 байт (-12,9 %); он не описывает размер текущего runtime.
# Проверки сборки секций выполняет scripts/check-router-builds.sh под QEMU.
# openssl-link-smoke отдельно проверяет, что статическая сборка сохраняет
# доступность ED25519; новый d2ktg этот алгоритм не использует.
# C-код не использует раскрутку стека; её отключение оставлено как отдельная
# оптимизация размера, которую нужно учитывать при изменении toolchain.
SIZE_CFLAGS='-ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables'
UNUSED_FEATURES='no-dsa no-cms no-ct no-ocsp no-srp no-comp no-engine no-dynamic-engine
    no-dtls no-ssl3 no-idea no-rc2 no-rc4 no-rc5 no-des no-bf no-cast no-camellia no-aria
    no-seed no-sm2 no-sm3 no-sm4 no-gost no-md4 no-mdc2 no-whirlpool no-ts no-rfc3779
    no-cmp no-quic no-nextprotoneg no-srtp no-sctp no-ocb no-siphash no-scrypt'

ASM_FLAGS=no-asm
case "$ARCH" in arm64|amd64) ASM_FLAGS= ;; esac
ATOMIC_FLAGS=
# 32-bit targets may not provide lock-free, unaligned 64-bit atomics. Use OpenSSL's existing
# pthread-lock fallback rather than requiring a router-side libatomic.
case "$ARCH" in mips|mipsel|x86) ATOMIC_FLAGS=-DBROKEN_CLANG_ATOMICS ;; esac
# shellcheck disable=SC2086
CC="$ZIG cc -target $TARGET $TARGET_FLAGS $SIZE_CFLAGS" \
AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    "$SRC_DIR/Configure" "$SSL_TARGET" no-shared no-tests no-apps no-docs no-legacy $UNUSED_FEATURES $ASM_FLAGS $ATOMIC_FLAGS \
    --prefix="$PREFIX" --openssldir=/opt/d2k/certs
make -j "$JOBS" build_libs
make install_sw

SMOKE="$ROOT/telegram/test_openssl_link.c"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
# TARGET_FLAGS is a controlled compiler option from build-target.sh.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static $SIZE_CFLAGS -Wl,--gc-sections \
    -I"$PREFIX/include" -L"$LIBDIR" \
    -o "$ROOT/build/telegram/openssl-link-smoke-$ARCH" "$SMOKE" \
    -lssl -lcrypto -ldl -pthread
file "$ROOT/build/telegram/openssl-link-smoke-$ARCH"

# The router runtime is the local MTProto proxy. Keep its source list explicit
# so relay registration and tunnelling code cannot enter the router binary.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -std=c11 \
    -Wall -Wextra -Werror -pedantic -Wl,-S $SIZE_CFLAGS -Wl,--gc-sections \
    -DD2K_RELEASE_ID="\"${RELEASE_ID:-dev}\"" \
    -I"$ROOT/telegram/include" -I"$PREFIX/include" -I"$ZLIB_PREFIX/include" \
    -o "$OUT/d2ktg-linux-$ARCH" \
    "$ROOT/telegram/src/main.c" \
    "$ROOT/telegram/src/config.c" \
    "$ROOT/telegram/src/tls.c" \
    "$ROOT/telegram/src/ws.c" \
    "$ROOT/telegram/src/ws_pump.c" \
    "$ROOT/telegram/src/net.c" \
    "$ROOT/telegram/src/listener.c" \
    "$ROOT/telegram/src/mtproto_crypto.c" \
    "$ROOT/telegram/src/mtproto_encrypted.c" \
    "$ROOT/telegram/src/mtproto_config.c" \
    "$ROOT/telegram/src/mtproto_probe.c" \
    "$ROOT/telegram/src/mtproto_auth.c" \
    "$ROOT/telegram/src/mtproto_splitter.c" \
    "$ROOT/telegram/src/dc_map.c" \
    "$ROOT/telegram/src/dc_map_json.c" \
    "$ROOT/telegram/src/dc_map_store.c" \
    "$ROOT/telegram/src/cf_domains.c" \
    "$ROOT/telegram/src/route_plan.c" \
    "$ROOT/telegram/src/route_dns.c" \
    "$ROOT/telegram/src/limits.c" \
    "$ROOT/telegram/src/epoll_proxy.c" \
    "$ROOT/telegram/src/transparent.c" \
    "$ROOT/telegram/src/stats_socket.c" \
    -L"$LIBDIR" -L"$ZLIB_PREFIX/lib" -lssl -lcrypto -lz -ldl -pthread
file "$OUT/d2ktg-linux-$ARCH"
