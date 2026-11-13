"""Проверка настоящего сериализатора C, без повторной реализации его вывода."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
with tempfile.TemporaryDirectory() as directory:
    dest = Path(directory) / 'report.json'
    telegram_dest = Path(directory) / 'telegram-report.json'
    subprocess.run([str(Path(__file__).resolve().parent / 'test_diagnostics')],
                   env=dict(os.environ, D2K_TEST_DIAG_JSON=str(dest),
                            D2K_TEST_TG_DIAG_JSON=str(telegram_dest)), check=True)
    report = json.loads(dest.read_text())
    telegram_report = json.loads(telegram_dest.read_text())
    assert report['schema'] == 1 and report['enabled'] is True
    assert report['ring_bytes'] <= 256 * 1024
    history = report['memory_history']
    assert history['capacity'] == 1440
    assert history['sample_interval_ms'] == 60000
    assert len(history['samples']) == 1440
    assert report['memory_history_overwritten'] == 1
    assert report['diagnostic_write_failures'] == 1
    assert report['memory_tracking']['enabled'] is True
    tg = telegram_report['telegram_diagnostics']
    assert telegram_report['enabled'] is True and telegram_report['general_enabled'] is False
    assert telegram_report['telegram_enabled'] is True
    assert tg['enabled'] is True and tg['collection_status'] == 'socket_unavailable'
    assert tg['collection_failures'] == 1 and tg['last_error'] == 110
    assert tg['memory_history']['fields'][2] == 'rss_kib'
    assert len(tg['memory_history']['samples']) == 2
    tg_fields = tg['memory_history']['fields']
    assert len(tg['memory_history']['samples'][0]) == len(tg_fields)
    tg_sample = dict(zip(tg_fields, tg['memory_history']['samples'][0]))
    assert tg_sample['process_id'] == 1234
    assert tg_sample['process_started_at'] == 1700000000
    assert tg_sample['process_generation'] == 987654321
    assert tg_sample['worker_pool_struct_bytes'] == 1024
    assert tg_sample['smaps_pss_kib'] == 'unavailable'
    assert 'smaps_pss_kib' in tg['unavailable_fields']
    assert tg_sample['smaps_private_dirty_kib'] == 64
    assert tg_sample['wss_attempts'] == 7
    assert tg_sample['client_response_latency_p95_us'] == 90000
    assert tg['memory_history']['samples'][0][2] == 1024
    assert tg['latest']['rss_kib'] == 1024
    assert tg['latest']['route_health'][0]['rss_kib'] == 999
    tcp_site = next(site for site in report['memory_tracking']['sites'] if site['id'] == 'tcp.worker_arg')
    assert (tcp_site['live_bytes'], tcp_site['live_objects'], tcp_site['created'], tcp_site['destroyed']) == (512, 1, 1, 0)
    assert report['madvise']['successes'] == 4
    assert report['madvise']['failures'] == 1
    assert report['madvise']['failed_requested_bytes'] == 4096
    assert report['madvise']['errno'] == [{'code': 12, 'count': 1}]
    assert report['anomalies'][-1]['kind'] == 'diagnostic-json-write-error'
    assert history['smaps_rollup_status_codes'] == ['not-read', 'unavailable', 'ok', 'parse-error', 'unsupported']
    assert len(history['time_base']) == 2
    assert history['fields'] == ['at_delta_s', 'mono_delta_s', 'rss_kib', 'vm_data_kib',
                                 'vm_swap_kib', 'smaps_rollup_status_code',
                                 'smaps_rollup_errno',
                                 'smaps_rollup_kib', 'rss_anon_kib', 'catalog_bytes',
                                 'http_bytes', 'snapshot_bytes', 'tracked_tcp_bytes',
                                 'tracked_quic_bytes', 'tracked_tls_bytes', 'tasks',
                                 'workers_live', 'workers_result_pending', 'workers_join_pending',
                                 'd2kc_epoch']
    assert history['samples'][0][0:2] == [0, 0]
    assert history['samples'][-1][1] == 86340
    assert history['time_base'][1] + history['samples'][-1][1] == 86400
    assert history['samples'][-1][2:5] == [4096, 4096, 0]
    assert len(history['samples'][-1]) == len(history['fields'])
    last_memory = dict(zip(history['fields'], history['samples'][-1]))
    assert last_memory['smaps_rollup_status_code'] == 2
    assert last_memory['smaps_rollup_errno'] is None
    assert last_memory['smaps_rollup_kib'] == [120, 100, 80, 64, 2]
    assert last_memory['rss_anon_kib'] == 3072
    assert last_memory['catalog_bytes'] == 9625
    assert last_memory['http_bytes'] == 5529
    assert last_memory['snapshot_bytes'] == 4096
    assert last_memory['tracked_tcp_bytes'] == 512
    assert last_memory['tracked_quic_bytes'] == 1024
    assert last_memory['tracked_tls_bytes'] == 1536
    assert last_memory['tasks'] == 2 and last_memory['workers_live'] == 3
    assert last_memory['workers_result_pending'] == 1 and last_memory['workers_join_pending'] == 1
    assert last_memory['d2kc_epoch'] == 0
    sample = report['samples'][0]
    assert sample['mem_total_kib'] == 65536
    assert sample['processes'][0]['rss_kib'] == 4096
    assert sample['processes'][1]['rss_kib'] is None
    assert sample['datapath_flows'] is None
    assert report['http_storage_limits']['records_bytes'] == 262144
    assert report['http_storage_limits']['failure_record_bytes'] == 8192
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
    assert sample['http_records_bytes'] == 4096
    assert sample['http_queue_bytes'] == 1024
    assert sample['http_record_limit_hits'] == 1
    assert sample['http_failure_record_limit_hits'] == 2
    assert sample['http_queue_limit_hits'] == 5
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
assert details['first']['mono_ms'] == 7620000
assert details['first']['rss_kib'] == 4096
assert details['latest']['mono_ms'] == 86400000
assert details['latest']['rss_kib'] == 4096
assert details['latest']['vm_size_kib'] == 8192
assert details['latest']['smaps'] is None
assert details['latest']['smaps_rollup']['anonymous_kib'] == 80
assert details['latest']['smaps_rollup']['private_dirty_kib'] == 64
assert details['latest']['smaps_rollup_status'] == 'ok'
assert details['latest']['smaps_rollup_source'] == 'smaps_rollup'
assert details['latest']['smaps_status'] == 'not-read'
assert details['latest']['fd_count'] == 2
assert report['memory_details'][1]['latest'] is None
assert 'never-export-me' not in json.dumps(report)
print('контракт подробных снимков памяти прошёл')
