#!/bin/sh
# Entware describes the userspace ABI; uname can describe a different kernel ABI.
# Without Entware, OpenWrt's own apk/opkg names it (aarch64_generic,
# mipsel_24kc, arm_cortex-a7_neon-vfpv4): the CPU after "_" picks no build.
# On firmware that names neither, install.sh reads the endianness and the class
# out of a system binary's ELF header and passes the result as $2.
set -eu
arch=${2:-${1:-}}
if [ "$arch" = mips ] && [ -z "${2:-}" ]; then
    # Entware is one way to name the ABI, not the only one, and OpenWrt has no
    # Entware opkg at all: name whatever this firmware does have.
    echo 'uname=mips does not identify endianness; name the userspace ABI:' >&2
    echo '  OpenWrt: DISTRIB_ARCH in /etc/openwrt_release, or "apk --print-arch"' >&2
    echo '  Entware: "opkg print-architecture"' >&2
    echo '  any firmware: ELF header of /bin/busybox (byte 5: 1 = little, 2 = big endian)' >&2
    exit 1
fi
case "$arch" in
    # OpenWrt ARMv5/ARMv6, i586: no build (check-cpu gates VFPv3 on the rest).
    arm_arm*|arm_fa526*|arm_xscale*|arm_mpcore*|i386_pentium-mmx*)
        echo "Unsupported userspace architecture: $arch (uname=${1:-unknown})" >&2; exit 1 ;;
    aarch64_*|arm_*|mipsel_*|mips_*|mips64el_*|i386_pentium4*|riscv64_*)
        arch=${arch%%_*}; [ "$arch" != i386 ] || arch=i686 ;;
esac
case "$arch" in
    aarch64|arm64|aarch64-*|arm64-*) echo arm64 ;;
    arm|armv7l|armv7|armv7-*|armv7sf-*|armv7hf-*|arm-*) echo arm ;;
    mips64el|mips64el-*|mipsel64|mipsel64-*) echo mips64el ;;
    # mipselsf в Entware Keenetic — little-endian MIPS с soft-float,
    # совместимый с нашей сборкой mipsel-linux-musleabi (+soft_float).
    mipsel|mipsel-*|mipselsf|mipselsf-*) echo mipsel ;;
    mips|mips-*) echo mips ;;
    x86_64|amd64|x64|x86_64-*|amd64-*|x64-*) echo amd64 ;;
    i686|x86|i686-*|x86-*) echo x86 ;;
    ppc64|ppc64-*) echo ppc64 ;;
    riscv64|riscv64-*) echo riscv64 ;;
    *) echo "Unsupported userspace architecture: $arch (uname=${1:-unknown})" >&2; exit 1 ;;
esac
