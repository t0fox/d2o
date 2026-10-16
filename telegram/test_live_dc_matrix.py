#!/usr/bin/env python3
"""Проверяет живую TCP resPQ-матрицу DC1–DC5 у собранного d2ktg."""

import json
import subprocess
import sys


EXPECTED = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
]


def main() -> int:
    if len(sys.argv) != 2:
        print("Использование: python3 test_live_dc_matrix.py /путь/к/d2ktg", file=sys.stderr)
        return 2

    try:
        result = subprocess.run(
            [sys.argv[1], "--check-telegram-dc-matrix"],
            capture_output=True,
            check=False,
            text=True,
            timeout=50,
        )
    except subprocess.TimeoutExpired:
        print("Проверка матрицы DC1–DC5 превысила 50 секунд", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Не удалось запустить d2ktg: {error}", file=sys.stderr)
        return 1

    try:
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        print(f"d2ktg вернул некорректный JSON: {error}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return 1

    actual = [(record.get("dc"), record.get("address")) for record in records]
    if actual != EXPECTED:
        print(f"Неверная матрица DC: {actual!r}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return 1
    if result.returncode != 0 or any(
        record.get("ok") is not True or record.get("stage") != "resPQ"
        for record in records
    ):
        print("Не все пять DC прошли TCP и MTProto resPQ", file=sys.stderr)
        for record in records:
            print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
        return 1

    print("Живая TCP resPQ-проверка DC1–DC5: ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
