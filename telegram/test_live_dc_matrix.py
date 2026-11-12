#!/usr/bin/env python3
"""Проверяет получение карты DC через настроенные Cloudflare-маршруты."""

import argparse
import json
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("d2ktg")
    parser.add_argument("config", nargs="?", default="/opt/d2k/config")
    args = parser.parse_args()
    try:
        result = subprocess.run(
            [args.d2ktg, "--check-telegram-dc-map", args.config],
            capture_output=True, check=False, text=True, timeout=110,
        )
        record = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        return 1
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    return 0 if (result.returncode == 0 and record.get("ok") is True
                 and record.get("stage") == "help.getConfig"
                 and record.get("endpoint_count", 0) > 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
