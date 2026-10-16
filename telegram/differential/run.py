#!/usr/bin/env python3
"""Сверяет C-кадрирование MTProto с закреплённой Rust-реализацией."""

from __future__ import annotations

import argparse
import difflib
import io
import os
from pathlib import Path, PurePosixPath
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


DONOR_URL = "https://github.com/t0fox/z2kOW.git"
DONOR_COMMIT = "4ef79fb99c30c233488623c04ec13c8097a614e0"
DONOR_SUBTREE = PurePosixPath("platform/openwrt/tg-proxy")
ROOT = Path(__file__).resolve().parents[2]


def command(args: list[str], *, cwd: Path | None = None, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def frame(proto: str, payload: bytes) -> bytes:
    if proto == "abridged":
        if len(payload) % 4:
            raise ValueError("длина Abridged payload должна быть кратна четырём")
        words = len(payload) // 4
        if words < 0x7F:
            header = bytes([words])
        else:
            header = b"\x7f" + words.to_bytes(3, "little")
    else:
        length = len(payload)
        if proto == "padded-intermediate":
            length |= 0x80000000
        header = length.to_bytes(4, "little")
    return header + payload


def chunks(data: bytes, rng: random.Random, *, tiny: bool = False) -> list[bytes]:
    result = []
    offset = 0
    while offset < len(data):
        width = rng.randint(1, 5) if tiny else rng.randint(1, 83)
        result.append(data[offset : offset + width])
        offset += width
    return result


def corpus() -> str:
    rng = random.Random(0xD20C11)
    cases: list[tuple[str, str, list[bytes]]] = []
    for proto in ("abridged", "intermediate", "padded-intermediate"):
        for index in range(45):
            packets = []
            for packet_index in range(rng.randint(1, 5)):
                if proto == "abridged":
                    words = rng.choice((1, 2, 3, 31, 63, 126, 127, 200))
                    payload = rng.randbytes(words * 4)
                else:
                    length = rng.randint(1, 1024)
                    payload = rng.randbytes(length)
                packets.append(frame(proto, payload))
            stream = b"".join(packets)
            cases.append((f"{proto}-{index}", proto, chunks(stream, rng, tiny=index % 7 == 0)))

    for proto in ("abridged", "intermediate", "padded-intermediate"):
        zero = b"\x00" if proto == "abridged" else b"\x00\x00\x00\x00"
        cases.append((f"{proto}-raw", proto, [zero + rng.randbytes(79), rng.randbytes(113)]))

        complete = frame(proto, rng.randbytes(32 if proto == "abridged" else 37))
        incomplete = (b"\x20" if proto == "abridged" else (37).to_bytes(4, "little")) + rng.randbytes(11)
        cases.append((f"{proto}-partial-eof", proto, chunks(complete + incomplete, rng, tiny=True)))

        if proto == "abridged":
            too_many_words = (4 * 1024 * 1024) // 4 + 1
            oversized = b"\x7f" + too_many_words.to_bytes(3, "little")
        else:
            oversized_len = 4 * 1024 * 1024 + 1
            if proto == "padded-intermediate":
                oversized_len |= 0x80000000
            oversized = oversized_len.to_bytes(4, "little")
        cases.append((f"{proto}-oversize", proto, [oversized]))

    lines = []
    for case_id, proto, pieces in cases:
        key = rng.randbytes(32).hex()
        iv = rng.randbytes(16).hex()
        piece_field = ";".join(piece.hex() for piece in pieces)
        lines.append(f"{case_id}\t{proto}\t{key}\t{iv}\t{piece_field}")
    return "\n".join(lines) + "\n"


def extract_donor(repo: Path, target: Path) -> Path:
    found = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{DONOR_COMMIT}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if found != DONOR_COMMIT:
        raise RuntimeError(f"Rust donor HEAD не совпал: {found}")

    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", DONOR_COMMIT, str(DONOR_SUBTREE)],
        check=True,
        capture_output=True,
    ).stdout
    donor_dir = target / "platform" / "openwrt" / "tg-proxy"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path in DONOR_SUBTREE.parents:
                continue
            try:
                relative = member_path.relative_to(DONOR_SUBTREE)
            except ValueError as error:
                raise RuntimeError(f"архив содержит неожиданный путь: {member.name}") from error
            destination = donor_dir.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise RuntimeError(f"не удалось прочитать {member.name}")
                with source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)
                destination.chmod(member.mode & 0o777)
            else:
                raise RuntimeError(f"неподдерживаемый тип файла в архиве: {member.name}")
    return donor_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--donor-repo",
        type=Path,
        help="уже загруженный клон t0fox/z2kOW; используется только для чтения",
    )
    options = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="d2o-tg-differential-") as temp_name:
        temp = Path(temp_name)
        donor_repo = options.donor_repo
        if donor_repo is None:
            donor_repo = temp / "donor-repo"
            command(
                ["git", "clone", "--filter=blob:none", "--no-checkout", DONOR_URL, str(donor_repo)],
                stdout=subprocess.DEVNULL,
            )
        donor = extract_donor(donor_repo.resolve(), temp / "source")

        rust_bin_dir = donor / "src" / "bin"
        rust_bin_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(__file__).parent / "rust" / "main.rs", rust_bin_dir / "d2o-differential.rs")

        c_binary = temp / "c-differential"
        command(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-D_POSIX_C_SOURCE=200809L",
                f"-I{ROOT / 'telegram' / 'include'}",
                str(Path(__file__).parent / "c" / "main.c"),
                str(ROOT / "telegram" / "src" / "mtproto_crypto.c"),
                str(ROOT / "telegram" / "src" / "mtproto_splitter.c"),
                "-lcrypto",
                "-o",
                str(c_binary),
            ]
        )

        test_input = corpus().encode()
        c_output = command([str(c_binary)], input=test_input, capture_output=True).stdout.decode()
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(temp / "cargo-target")
        toolchain_file = donor / "rust-toolchain.toml"
        env["RUSTUP_TOOLCHAIN"] = tomllib.loads(toolchain_file.read_text())["toolchain"]["channel"]
        rust_output = command(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(donor / "Cargo.toml"),
                "--bin",
                "d2o-differential",
            ],
            cwd=donor,
            input=test_input,
            capture_output=True,
            env=env,
        ).stdout.decode()

        if c_output != rust_output:
            diff = difflib.unified_diff(
                rust_output.splitlines(),
                c_output.splitlines(),
                fromfile="Rust",
                tofile="C",
                lineterm="",
            )
            print("\n".join(diff), file=sys.stderr)
            return 1

        case_count = len(test_input.splitlines())
        print(f"C/Rust: совпали {case_count} воспроизводимых сценариев MTProto framing; donor {DONOR_COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
