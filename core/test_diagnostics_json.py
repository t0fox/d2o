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
    assert sample['catalog_bytes'] == 8192
    assert sample['snapshot_bytes'] == 4096
    assert sample['workers_running'] == 2
    assert sample['workers_live'] == 3
    assert sample['workers_join_pending'] == 1
    assert sample['workers_result_pending'] == 1
    assert sample['worker_oldest_age_ms'] == 600
    assert sample['worker_oldest_type'] == 'TCP'
    assert sample['last_measurement_age_ms'] == 1250
    assert sample['http_failures'] == 3
    assert sample['http_bytes'] == 16384
    assert sample['http_failure_limit_hits'] == 4
    assert sample['http_failure_bytes'] == 2048
    assert sample['measurement_limit'] == 1
    assert sample['measurement_slots'] == 64
    assert sample['scheduler_mem_avail_kib'] == 8192
    assert sample['scheduler_mem_total_kib'] == 65536
    assert sample['scheduler_mem_reserve_kib'] == 32768
    assert sample['limit_reason'] == ['memory', 'conntrack']
    assert sample['task_states']['free'] == 62
    assert sample['task_states']['watching'] == 2
    assert report['events'][0]['target'] == 'bad�name'
    assert report['samples'][1]['processes'][0]['vm_data_kib'] == 4096
    assert report['samples'][1]['processes'][0]['vm_swap_kib'] == 0
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
assert details['latest']['smaps_rollup_status'] == 'unavailable'
assert details['latest']['smaps_status'] == 'ok'
assert details['latest']['fd_count'] is None
assert report['memory_details'][1]['latest'] is None
assert 'never-export-me' not in json.dumps(report)
print('контракт подробных снимков памяти прошёл')
