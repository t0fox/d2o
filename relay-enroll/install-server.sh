#!/bin/sh
# Run on the existing relay VPS with the compiled d2k-enroll and service file
# in the supplied directory. The bootstrap key never leaves this server.
set -eu
set +x
bundle=${1:?usage: install-server.sh BUNDLE_DIRECTORY}
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
[ -s /etc/z2k/secrets.env ] || { echo 'existing relay credential file missing' >&2; exit 1; }
[ -s /var/lib/z2k-relay/acme/192.0.2.44.nip.io ] || { echo 'relay TLS certificate missing' >&2; exit 1; }
umask 077
mkdir -p /etc/d2k-enroll
# shellcheck disable=SC1091
. /etc/z2k/secrets.env
[ -n "${Z2K_SECRET:-}" ] || { echo 'relay bootstrap credential missing' >&2; exit 1; }
printf '%s' "$Z2K_SECRET" > /etc/d2k-enroll/bootstrap.key.new
chmod 0600 /etc/d2k-enroll/bootstrap.key.new
mv /etc/d2k-enroll/bootstrap.key.new /etc/d2k-enroll/bootstrap.key
install -m 0755 "$bundle/d2k-enroll" /usr/local/bin/d2k-enroll.new
mv /usr/local/bin/d2k-enroll.new /usr/local/bin/d2k-enroll
install -m 0644 "$bundle/d2k-enroll.service" /etc/systemd/system/d2k-enroll.service
systemctl daemon-reload
systemctl enable d2k-enroll.service
systemctl restart d2k-enroll.service
systemctl is-active d2k-enroll.service
