"""Проверка настоящего сериализатора C, без повторной реализации его вывода."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
with tempfile.TemporaryDirectory() as directory:
    dest = Path(directory) / 'report.json'
    subprocess.run([str(Path(__file__).resolve().parent / 'test_diagnostics')],
                   env=dict(os.environ, D2K_TEST_DIAG_JSON=str(dest)), check=True)
    report = json.loads(dest.read_text())
    assert report['schema'] == 1 and report['enabled'] is True
    assert report['ring_bytes'] <= 128 * 1024
    sample = report['samples'][0]
    assert sample['mem_total_kib'] == 65536
    assert sample['processes'][0]['rss_kib'] == 1024
    assert sample['processes'][1]['rss_kib'] is None
    assert sample['datapath_flows'] is None
    assert sample['system_conntrack'] is None
print('JSON диагностики: сериализатор прошёл')

details = report['memory_details'][0]
assert details['name'] == 'd2kc'
assert details['first']['mono_ms'] == 0
assert details['first']['rss_kib'] == 1024
assert details['latest']['mono_ms'] == 60000
assert details['latest']['rss_kib'] == 4096
assert details['latest']['vm_size_kib'] == 8192
assert details['latest']['smaps']['heap']['rss_kib'] == 8
assert details['latest']['smaps']['anonymous']['rss_kib'] == 24
assert details['latest']['smaps']['other']['rss_kib'] == 4
assert details['latest']['fd_count'] is None
assert report['memory_details'][1]['latest'] is None
assert 'never-export-me' not in json.dumps(report)
print('контракт подробных снимков памяти прошёл')
