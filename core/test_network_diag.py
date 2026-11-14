"""Exercise production parsers and the exported history field contract."""
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture = {
            "proc/net/netfilter/nfnetlink_queue": (
                "2000 99999 30 2 1600 22 33 44 1\n"
                "2000 12345 12 2 1600 2 3 4 1\n"
            ),
            "proc/net/netlink": "hash 12 12345 0 120 0 0 2 8 123\n",
            "proc/sys/net/netfilter/nf_conntrack_count": "256\n",
            "proc/sys/net/netfilter/nf_conntrack_max": "4096\n",
            "proc/net/stat/nf_conntrack": (
                "entries early_drop found insert_failed drop\n"
                "100 00000004 0 00000000 00000011\n"
                "100 00000001 0 00000003 00000000\n"
            ),
            "proc/net/route": (
                "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
                "other 00000000 00000000 0001 0 0 100 00000000\n"
                "wan0 00000000 00000000 0003 0 0 10 00000000\n"
            ),
            "proc/net/ipv6_route": (
                f"{'0'*32} 00 {'0'*32} 00 {'0'*32} ffffffff 1 0 00200201 lo\n"
            ),
            "run/d2k.pid": "22\n",
            "proc/22/stat": "22 (d2kc) S " + "0 " * 10 + "20 10 " + "0 " * 6 + "7\n",
            "sys/class/net/wan0/ifindex": "9\n",
            "sys/class/net/wan0/operstate": "up\n",
            "sys/class/net/wan0/carrier": "1\n",
            "sys/class/net/wan0/statistics/tx_dropped": "5\n",
        }
        for relative, value in fixture.items():
            dest = root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(value)
        argv = [str(Path(__file__).with_name("test_network_diag")), *(str(root / k) for k in ("proc", "sys", "run"))]
        # Resolve the binary path when Make invokes this from core/.
        argv[0] = str(Path(argv[0]).resolve())
        report = json.loads(subprocess.check_output(argv))
        rows = report["samples"]
        assert len(rows) == report["capacity"] == 240 and report["overwritten"] == 3
        assert report["ring_bytes"] <= 176 * 1024
        assert rows[-1][1] - rows[0][1] >= 300000
        assert "wan0" not in json.dumps(report)
        parsed = [dict(zip(report["fields"], row, strict=True)) for row in rows]
        assert parsed[0]["nfqueue"] is None  # stale
        queue_fields = report["nfqueue_fields"]
        q = dict(zip(queue_fields, parsed[1]["nfqueue"], strict=True))
        assert q["backlog"] == 12 and q["fail_open"] == 1
        assert [q[k] for k in ("kernel_drops", "kernel_user_drops", "netlink_socket_drops")] == [2, 3, 8]
        assert q["kernel_packet_to_verdict_max_us"] == 99
        q = dict(zip(queue_fields, parsed[2]["nfqueue"], strict=True))
        assert q["kernel_packet_to_verdict_max_us"] is None  # same sender window
        assert parsed[-1]["cpu_pct_one_core"] == [0, None, None, None, None]
        assert parsed[-1]["conntrack"] == [256, 4096, 17, 5, 3]
        assert parsed[-1]["wan4"] == [2, 9, 6, 1, None, None, None, 5]
        assert parsed[-1]["wan6"] == [0, None, None, None, None, None, None, None]
        ctl = dict(zip(report["controller_fields"], parsed[-1]["controller"], strict=True))
        assert ctl["encrypted_dns_checks_without_valid_reply"] == 242
        assert ctl["mem_available_kib"] is None
        # Absent procfs files remain null even when the daemon is reporting.
        (root / "proc/net/netlink").unlink()
        (root / "proc/net/netfilter/nfnetlink_queue").unlink()
        (root / "proc/net/route").unlink()
        gaps = json.loads(subprocess.check_output(argv))
        q = dict(zip(queue_fields, gaps["samples"][1][-2], strict=True))
        assert q["backlog"] is None and q["netlink_socket_drops"] is None
        assert gaps["samples"][1][4] == [None] * 8
    print("network diagnostics: history, procfs, missing sources and stale IPC OK")


if __name__ == "__main__":
    main()
