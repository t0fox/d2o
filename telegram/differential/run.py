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
DONOR_COMMIT = "9fc14bb67c3147b51d6d022575c9bba8f8f9ed2d"
DONOR_SUBTREE = PurePosixPath("platform/openwrt/tg-proxy")
TEST_SECRET = "2a519e5be6c3219c69879e5fa2a0eab8"
WS_MAX_MESSAGE = 4 * 1024 * 1024
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


def handshake_requests() -> str:
    requests = []
    dc_ids = (1, 2, 3, 4, 5, -1, -2, -3, -4, -5)
    for proto in ("abridged", "intermediate", "padded-intermediate"):
        for dc_id in dc_ids:
            case_id = f"{proto}-{dc_id}"
            requests.append(f"secret\tsecret-{case_id}\t{proto}\t{dc_id}\t{TEST_SECRET}")
            requests.append(f"direct\tdirect-{case_id}\t{proto}\t{dc_id}")
    return "\n".join(requests) + "\n"


BUILTIN_DC_ROUTES = (
    (1, "149.154.175.50", 0), (1, "149.154.175.51", 0),
    (1, "149.154.175.52", 1), (1, "149.154.175.53", 0),
    (1, "149.154.175.54", 0), (2, "149.154.167.41", 0),
    (2, "149.154.167.50", 0), (2, "149.154.167.51", 0),
    (2, "149.154.167.220", 0), (2, "95.161.76.100", 0),
    (2, "149.154.167.151", 1), (2, "149.154.167.222", 1),
    (2, "149.154.167.223", 1), (2, "149.154.162.123", 1),
    (3, "149.154.175.100", 0), (3, "149.154.175.101", 0),
    (3, "149.154.175.102", 1), (4, "149.154.167.91", 0),
    (4, "149.154.167.92", 0), (4, "149.154.164.250", 1),
    (4, "149.154.166.120", 1), (4, "149.154.166.121", 1),
    (4, "149.154.167.118", 1), (4, "149.154.165.111", 1),
    (5, "91.108.56.100", 0), (5, "91.108.56.101", 0),
    (5, "91.108.56.116", 0), (5, "91.108.56.126", 0),
    (5, "149.154.171.5", 0), (5, "91.108.56.102", 1),
    (5, "91.108.56.128", 1), (5, "91.108.56.151", 1),
    (203, "91.105.192.100", 0),
)


def dc_map_corpus() -> str:
    cases: list[str] = []

    def add(case_id, source, address, port, media, dc, endpoints=()):
        encoded = "/".join(
            ",".join(str(value) for value in endpoint) for endpoint in endpoints
        )
        cases.append(
            f"{case_id}\t{source}\t{address}\t{port}\t{media}\t{dc}\t{encoded}"
        )

    for index, (dc, address, _media_only) in enumerate(BUILTIN_DC_ROUTES):
        for media in (0, 1):
            add(f"builtin-{index}-media-{media}", "builtin", address, 443, media, 0)
        add(f"builtin-{index}-wrong-dc", "builtin", address, 443, 1,
            2 if dc == 203 else dc + 1)

    add("builtin-unlisted", "builtin", "149.154.167.99", 443, 1, 0)
    add("builtin-unlisted-v6", "builtin", "2001:db8::9", 443, 1, 0)

    regular = (2, "149.154.167.240", 443, 0, 0, 0, 0, 0)
    media = (2, "149.154.167.241", 443, 1, 0, 0, 0, 0)
    restricted = (3, "149.154.167.242", 5222, 0, 1, 0, 0, 1)
    cdn = (3, "149.154.167.243", 443, 0, 0, 1, 0, 0)
    ipv6 = (4, "2001:b28:f23d:f001::a", 443, 0, 0, 0, 0, 0)
    conflict_a = (2, "149.154.167.244", 443, 0, 0, 0, 0, 0)
    conflict_b = (3, "149.154.167.244", 443, 0, 0, 0, 0, 0)
    port_general = (2, "149.154.167.245", 443, 0, 0, 0, 0, 0)
    port_specific = (2, "149.154.167.245", 5222, 0, 1, 0, 1, 1)
    conflicting_cdn = (2, "149.154.167.246", 443, 0, 0, 1, 0, 0)
    conflicting_regular = (2, "149.154.167.246", 443, 0, 0, 0, 0, 0)

    add("official-regular", "official", regular[1], 443, 0, 0, [regular])
    add("official-wrong-dc", "official", regular[1], 443, 0, 3, [regular])
    add("official-unlisted", "official", "149.154.167.247", 443, 0, 0, [regular])
    add("official-media-rejected", "official", media[1], 443, 0, 0, [media])
    add("official-media-accepted", "official", media[1], 443, 1, 2, [media])
    add("official-media-wrong-dc", "official", media[1], 443, 1, 3, [media])
    add("official-port-rejected", "official", restricted[1], 443, 0, 0, [restricted])
    add("official-port-accepted", "official", restricted[1], 5222, 0, 3, [restricted])
    add("official-cdn-rejected", "official", cdn[1], 443, 0, 0, [cdn])
    add("official-v6", "official", ipv6[1], 443, 0, 4, [ipv6])
    add("official-ambiguous", "official", conflict_a[1], 443, 0, 0,
        [conflict_a, conflict_b])
    add("official-ambiguous-narrowed", "official", conflict_a[1], 443, 0, 3,
        [conflict_a, conflict_b])
    add("official-specific-port-selected", "official", port_general[1], 5222, 0, 2,
        [port_general, port_specific])
    add("official-general-port-selected", "official", port_general[1], 443, 0, 2,
        [port_general, port_specific])
    add("official-flag-ambiguity", "official", conflicting_cdn[1], 443, 0, 0,
        [conflicting_cdn, conflicting_regular])
    return "\n".join(cases) + "\n"



def websocket_frame(opcode: int, payload: bytes = b"", *, fin: bool = True) -> bytes:
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, length))
    elif length <= 0xFFFF:
        header = bytes((first, 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((first, 127)) + length.to_bytes(8, "big")
    return header + payload


def websocket_corpus() -> str:
    close = websocket_frame(0x8)
    cases: list[tuple[str, int, bytes]] = []

    def add(case_id: str, wire: bytes, chunk: int = 7) -> None:
        cases.append((case_id, chunk, wire))

    add("binary", websocket_frame(0x2, b"mtproto") + close, 1)
    add(
        "binary-fragments-ping-pong",
        websocket_frame(0x2, b"mtproto-", fin=False)
        + websocket_frame(0x9, b"p")
        + websocket_frame(0x0, b"payload", fin=True)
        + websocket_frame(0xA, b"p")
        + close,
        3,
    )
    add(
        "empty-fragments",
        websocket_frame(0x2, b"", fin=False)
        + websocket_frame(0x0, b"part-", fin=False)
        + websocket_frame(0x9, b"")
        + websocket_frame(0x0, b"end", fin=True)
        + close,
        2,
    )
    text = "Telegram ✓".encode()
    add(
        "text-utf8-split",
        websocket_frame(0x1, text[:-1], fin=False)
        + websocket_frame(0x0, text[-1:], fin=True)
        + close,
        1,
    )
    add("empty-binary", websocket_frame(0x2) + close, 2)
    add("length-125", websocket_frame(0x2, b"a" * 125) + close, 31)
    add("length-126", websocket_frame(0x2, b"b" * 126) + close, 37)
    add("length-65535", websocket_frame(0x2, b"c" * 65535) + close, 4093)
    add("length-65536", websocket_frame(0x2, b"d" * 65536) + close, 8191)
    add("invalid-continuation", websocket_frame(0x0, b"x") + close)
    add(
        "invalid-nested-binary",
        websocket_frame(0x2, b"a", fin=False)
        + websocket_frame(0x2, b"b")
        + close,
    )
    add("invalid-fragmented-ping", websocket_frame(0x9, b"p", fin=False) + close)
    add("invalid-rsv", b"\xc2\x00" + close)
    add("invalid-masked-server-frame", b"\x82\x80\x00\x00\x00\x00" + close)
    add("invalid-text-utf8", websocket_frame(0x1, b"\xc0\x80") + close)
    add("invalid-close-one-byte", websocket_frame(0x8, b"\x03"))
    add("invalid-close-utf8", websocket_frame(0x8, b"\x03\xe8\xff"))
    add("incomplete-header", b"\x82")
    add("incomplete-payload", b"\x82\x05ab")
    first_len = WS_MAX_MESSAGE // 2 + 1
    second_len = WS_MAX_MESSAGE - first_len + 1
    add(
        "message-limit",
        websocket_frame(0x2, b"x" * first_len, fin=False)
        + websocket_frame(0x0, b"y" * second_len)
        + close,
        131071,
    )

    rng = random.Random(0xD20F12)
    for index in range(24):
        length = rng.randint(2, 2048)
        payload = rng.randbytes(length)
        part_count = rng.randint(2, min(8, length))
        cuts = sorted(rng.sample(range(1, length), part_count - 1))
        boundaries = [0, *cuts, length]
        wire = bytearray()
        for part_index, (start, end) in enumerate(zip(boundaries, boundaries[1:])):
            final = part_index == part_count - 1
            wire.extend(
                websocket_frame(
                    0x2 if part_index == 0 else 0x0,
                    payload[start:end],
                    fin=final,
                )
            )
            if not final and rng.random() < 0.65:
                wire.extend(websocket_frame(0x9, rng.randbytes(rng.randint(0, 8))))
        wire.extend(close)
        add(f"random-fragments-{index}", bytes(wire), rng.randint(1, 257))

    return "\n".join(
        f"{case_id}\t{chunk}\t{wire.hex()}" for case_id, chunk, wire in cases
    ) + "\n"

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
        shutil.copyfile(Path(__file__).parent / "rust" / "dc_map.rs", rust_bin_dir / "d2o-dc-map-differential.rs")
        shutil.copyfile(Path(__file__).parent / "rust" / "ws_frames.rs", rust_bin_dir / "d2o-ws-frame-differential.rs")

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
                str(ROOT / "telegram" / "src" / "memory_budget.c"),
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

        ws_input = websocket_corpus().encode()
        c_ws_binary = temp / "c-ws-frame-differential"
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
                str(Path(__file__).parent / "c" / "ws_frames.c"),
                str(ROOT / "telegram" / "src" / "ws_pump.c"),
                str(ROOT / "telegram" / "src" / "ws.c"),
                str(ROOT / "telegram" / "src" / "memory_budget.c"),
                "-lssl",
                "-lcrypto",
                "-o",
                str(c_ws_binary),
            ]
        )
        c_ws_output = command(
            [str(c_ws_binary)], input=ws_input, capture_output=True
        ).stdout.decode()
        rust_ws_output = command(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(donor / "Cargo.toml"),
                "--bin",
                "d2o-ws-frame-differential",
            ],
            cwd=donor,
            input=ws_input,
            capture_output=True,
            env=env,
        ).stdout.decode()
        if c_ws_output != rust_ws_output:
            diff = difflib.unified_diff(
                rust_ws_output.splitlines(),
                c_ws_output.splitlines(),
                fromfile="Rust WebSocket",
                tofile="C WebSocket",
                lineterm="",
            )
            print("\n".join(diff), file=sys.stderr)
            return 1

        handshake_vectors = command(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(donor / "Cargo.toml"),
                "--bin",
                "d2o-differential",
                "--",
                "--generate-handshakes",
            ],
            cwd=donor,
            input=handshake_requests().encode(),
            capture_output=True,
            env=env,
        ).stdout.decode()

        c_handshake_lines = []
        rust_handshake_lines = []
        for line in handshake_vectors.splitlines():
            fields = line.split("\t")
            if fields[0] == "secret" and len(fields) == 8:
                _, case_id, proto, dc_id, media, prekey, handshake, wrong_secret = fields
                c_handshake_lines.extend(
                    (
                        f"secret\t{case_id}\t{TEST_SECRET}\t{handshake}",
                        f"secret\t{case_id}-wrong\t{wrong_secret}\t{handshake}",
                    )
                )
                rust_handshake_lines.extend(
                    (
                        f"{case_id}\tSECRET\tOK\t{proto}\t{dc_id}\t{media}\t{prekey}",
                        f"{case_id}-wrong\tSECRET\tREJECT",
                    )
                )
            elif fields[0] == "direct" and len(fields) == 7:
                _, case_id, proto, dc_id, media, prekey, handshake = fields
                c_handshake_lines.append(f"direct\t{case_id}\t{handshake}")
                rust_handshake_lines.append(
                    f"{case_id}\tDIRECT\tOK\t{proto}\t{dc_id}\t{media}\t{prekey}"
                )
            else:
                raise RuntimeError(f"неверный Rust handshake vector: {line}")

        c_handshake_output = command(
            [str(c_binary)],
            input=("\n".join(c_handshake_lines) + "\n").encode(),
            capture_output=True,
        ).stdout.decode()
        rust_handshake_output = "\n".join(rust_handshake_lines) + "\n"
        if c_handshake_output != rust_handshake_output:
            diff = difflib.unified_diff(
                rust_handshake_output.splitlines(),
                c_handshake_output.splitlines(),
                fromfile="Rust handshake",
                tofile="C handshake",
                lineterm="",
            )
            print("\n".join(diff), file=sys.stderr)
            return 1

        dc_map_input = dc_map_corpus().encode()
        c_dc_binary = temp / "c-dc-map-differential"
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
                str(Path(__file__).parent / "c" / "dc_map.c"),
                str(ROOT / "telegram" / "src" / "dc_map.c"),
                "-o",
                str(c_dc_binary),
            ]
        )
        c_dc_output = command(
            [str(c_dc_binary)], input=dc_map_input, capture_output=True
        ).stdout.decode()
        rust_dc_output = command(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(donor / "Cargo.toml"),
                "--bin",
                "d2o-dc-map-differential",
            ],
            cwd=donor,
            input=dc_map_input,
            capture_output=True,
            env=env,
        ).stdout.decode()
        if c_dc_output != rust_dc_output:
            diff = difflib.unified_diff(
                rust_dc_output.splitlines(),
                c_dc_output.splitlines(),
                fromfile="Rust DC map",
                tofile="C DC map",
                lineterm="",
            )
            print("\n".join(diff), file=sys.stderr)
            return 1

        case_count = len(test_input.splitlines())
        print(
            f"C/Rust: совпали {case_count} framing-сценариев, "
            f"{len(ws_input.splitlines())} WebSocket-сценариев, "
            f"{len(rust_handshake_lines)} проверок Obfuscated2 и "
            f"{len(dc_map_input.splitlines())} сценариев карты DC; "
            f"donor {DONOR_COMMIT}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
