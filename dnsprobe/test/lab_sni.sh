#!/bin/sh
# lab_sni.sh — доказательство выбора SNI-режима на управляемом цензоре.
#
# 9443 сбрасывает ClientHello с SNI ровно "api.magicdns.ru" и пропускает
# "api.magicdns.ru."; 9444 — настоящий TLS/DoH-сервер с сертификатом этого
# имени. Поиск обязан увидеть reset на canon и выбрать dot.
set -eu
cd "$(dirname "$0")/.."
LAB=/tmp/d2k-lab
rm -rf "$LAB"
mkdir -p "$LAB"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$LAB/key.pem" -out "$LAB/cert.pem" \
    -subj "/CN=api.magicdns.ru" \
    -addext "subjectAltName=DNS:api.magicdns.ru" >/dev/null 2>&1
python3 test/lab_censor.py >"$LAB/log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT INT TERM
sleep 1
printf 'lab-doh|api.magicdns.ru|127.0.0.1|doh|/sync||9443\n' >"$LAB/manifest"
./build/d2k-dnsprobe search "$LAB/manifest" --repeats 1
