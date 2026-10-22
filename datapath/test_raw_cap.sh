#!/bin/sh
# Изолированный тест предела MTU; интерфейсы существуют только в namespace.
set -eu
cd "$(dirname "$0")"
[ -x ./test_raw_cap ] || { echo "test_raw_cap не собран: make test-raw-cap-linux" >&2; exit 2; }
exec unshare -n sh -eu -c '
  ip link set lo up
  ip link add d2klow type dummy
  ip link set d2klow mtu 1280 up
  ip link add d2kout type dummy
  ip link set d2kout mtu 1500 up
  ./test_raw_cap d2kout d2klow
'
