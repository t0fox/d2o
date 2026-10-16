#!/usr/bin/env python3
"""Проверяет живые TCP resPQ и help.getConfig для DC1–DC5 у собранного d2ktg."""

import json
import subprocess
import sys
from pathlib import Path


EXPECTED = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
]


def check_matrix(executable: str, option: str, stage: str) -> bool:
    try:
        result = subprocess.run(
            [executable, option],
            capture_output=True,
            check=False,
            text=True,
            timeout=50,
        )
    except subprocess.TimeoutExpired:
        print(f"{option}: проверка DC1–DC5 превысила 50 секунд", file=sys.stderr)
        return False
    except OSError as error:
        print(f"Не удалось запустить d2ktg: {error}", file=sys.stderr)
        return False

    try:
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        print(f"{option}: d2ktg вернул некорректный JSON: {error}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return False

    actual = [(record.get("dc"), record.get("address")) for record in records]
    if actual != EXPECTED:
        print(f"{option}: неверная матрица DC: {actual!r}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return False
    if result.returncode != 0 or any(
        record.get("ok") is not True or record.get("stage") != stage
        for record in records
    ):
        print(f"{option}: не все пять DC прошли этап {stage}", file=sys.stderr)
        for record in records:
            print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
        return False
    if stage == "help.getConfig" and any(
        record.get("this_dc") != record.get("dc") or record.get("endpoint_count", 0) < 1
        for record in records
    ):
        print(f"{option}: неверная конфигурация одного из DC", file=sys.stderr)
        for record in records:
            print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
        return False
    return True


def check_wss_matrix(executable: str, ca_bundle: str) -> bool:
    option = "--check-telegram-wss-matrix"
    try:
        result = subprocess.run(
            [executable, option, ca_bundle],
            capture_output=True,
            check=False,
            text=True,
            timeout=50,
        )
    except subprocess.TimeoutExpired:
        print(f"{option}: проверка DC1–DC5 превысила 50 секунд", file=sys.stderr)
        return False
    except OSError as error:
        print(f"Не удалось запустить d2ktg: {error}", file=sys.stderr)
        return False

    try:
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        print(f"{option}: d2ktg вернул некорректный JSON: {error}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return False

    expected = [(dc, f"kws{dc}.web.telegram.org") for dc in range(1, 6)]
    actual = [(record.get("dc"), record.get("host")) for record in records]
    if actual != expected:
        print(f"{option}: неверная матрица DC: {actual!r}", file=sys.stderr)
        return False
    if result.returncode != 0 or any(
        record.get("ok") is not True
        or record.get("stage") != "resPQ"
        or record.get("route") != "direct_wss"
        for record in records
    ):
        print(f"{option}: не все пять DC вернули MTProto resPQ по WSS", file=sys.stderr)
        for record in records:
            print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
        return False
    return True


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(
            "Использование: python3 test_live_dc_matrix.py /путь/к/d2ktg [CA_BUNDLE]",
            file=sys.stderr,
        )
        return 2

    ca_bundle = (
        sys.argv[2]
        if len(sys.argv) == 3
        else str(Path(__file__).resolve().parents[1] / "files" / "tg-roots.pem")
    )
    for option, stage in (
        ("--check-telegram-dc-matrix", "resPQ"),
        ("--discover-telegram-dc-matrix", "help.getConfig"),
    ):
        if not check_matrix(sys.argv[1], option, stage):
            return 1
    if not check_wss_matrix(sys.argv[1], ca_bundle):
        return 1

    print("Живые TCP/WSS resPQ и help.getConfig для DC1–DC5: ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
