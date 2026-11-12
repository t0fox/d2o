"use strict";
// Смысловые правила панели без браузера: что можно утверждать по снимку.
const assert = require('node:assert/strict');
const ui = require('../internal/web/assets/panel.js');

const snap = (over) => ({ engine_running: true, controller_running: true, live_fresh: true, mode: 'apply', ...over });

// Нет связи с датапатом — это отсутствие измерения, а не «ноль поисков».
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: false, link_note: 'движок не отдаёт состояние', searches: [{ target: 'x' }] } });
  assert.equal(m.linked, false);
  assert.deepEqual(m.searches, [], 'unlinked snapshot must not show searches as measured');
  assert.match(m.headline.join(''), /Нет связи/);
  assert.match(m.lede, /не «ноль поисков»/);
  assert.match(m.lede, /движок не отдаёт состояние/);
}
// Остановленный движок не выдаётся за работающий, даже если в снимке остались поиски.
{
  const m = ui.model({ snapshot: snap({ engine_running: false }), knowledge: { linked: false, searches: [] } });
  assert.match(m.headline.join(''), /остановлен/);
  assert.equal(m.lamp, 'bad');
}
// MODE=off объясняется словами конфигурации.
{
  const m = ui.model({ snapshot: snap({ engine_running: false, mode: 'off' }), knowledge: {} });
  assert.match(m.lede, /MODE=off/);
}
// Работающий трафик без блокировок — «поисков нет», без утверждения, что интернет работает.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [] } });
  assert.equal(m.hunting, 0);
  assert.doesNotMatch(m.lede + m.headline.join(''), /интернет работает|всё работает|сайты доступны/i);
}
// Подтверждённая задача, которая лишь наблюдает трафик, не считается идущим поиском.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'подтверждено, смотрим живой трафик' },
  ] } });
  assert.equal(m.hunting, 1);
  assert.match(m.headline.join(''), /1 поиск$/);
}
// Устаревший снимок отмечается, а не выдаётся за текущий.
{
  const m = ui.model({ snapshot: snap({ live_fresh: false }), knowledge: { linked: true } });
  assert.equal(m.lamp, 'warn');
  assert.match(m.state, /устарел/);
}
// Мусор вместо массивов не роняет модель.
{
  const m = ui.model({ snapshot: {}, knowledge: { linked: true, groups: { invalid: true }, boxes: 'x', searches: null } });
  assert.deepEqual(m.groups, []);
  assert.deepEqual(m.boxes, []);
  assert.deepEqual(ui.model(null).searches, []);
}

// uptime_seconds — время работы процесса панели, не движка: рядом с состоянием движка его нет.
{
  const m = ui.model({ snapshot: snap({ uptime_seconds: 10 }), knowledge: { linked: true } });
  assert.doesNotMatch(m.stateDetail, /10 с/, 'panel uptime must not be shown as engine uptime');
  assert.match(m.stateDetail, /режим: применение/);
  assert.equal(m.panelUptime, 10);
}
// Поиски в очереди замера отделены от идущих замеров.
{
  const m = ui.model({ snapshot: snap(), knowledge: { linked: true, searches: [
    { target: 'a', phase: 'распознаём поведение' },
    { target: 'b', phase: 'ожидает безопасного слота замера' },
    { target: 'c', phase: 'ожидает безопасного слота замера' },
  ] } });
  assert.equal(m.hunting, 3);
  assert.deepEqual(m.running.map(s => s.target), ['a']);
  assert.deepEqual(m.queued.map(s => s.target), ['b', 'c']);
  assert.match(m.lede, /2 ждут/);
}

// Шкала фаз: этапы оригинала распознаются целиком, голос — своей шкалой, неизвестное — без шкалы.
assert.equal(ui.trackFor('распознаём поведение').at, 2);
assert.equal(ui.trackFor('проверяем готовое узнанной коробки').at, 5);
assert.equal(ui.trackFor('проверяем выведенный план').at, 5);
assert.equal(ui.trackFor('подтверждено, смотрим живой трафик').at, 6);
assert.equal(ui.trackFor('приём голоса стоит, ждём разговора').voice, true);
assert.equal(ui.trackFor('новый этап из будущей сборки'), null);

// Протоколы и семейства адресов не сливаются.
assert.equal(ui.shapeLabel(1, 6), 'TLS 1.3');
assert.equal(ui.shapeLabel(2, 6), 'TLS 1.2');
assert.equal(ui.shapeLabel(3, 17), 'QUIC');
assert.equal(ui.shapeLabel(6, 6), 'TLS 1.3 + ECH');
assert.equal(ui.shapeLabel(0, 17), 'UDP', 'unknown shape must not be guessed as QUIC');
assert.equal(ui.shapeLabel(undefined, undefined), 'протокол не указан');
assert.equal(ui.dnsProtocolLabel('doh', 6, 443), 'DoH');
assert.equal(ui.dnsProtocolLabel('', 6, 853), 'DoT');
assert.equal(ui.dnsProtocolLabel('', 17, 853), 'DoQ');
assert.deepEqual(['doh', 'dot', 'doq'].map(p => ui.dnsProtocolClass(p, p === 'doq' ? 17 : 6, p === 'doh' ? 443 : 853)),
  ['dns-protocol-doh', 'dns-protocol-dot', 'dns-protocol-doq'], 'each encrypted DNS protocol gets a distinct color class');
assert.deepEqual(ui.dnsProtocolCounts([
  { protocol: 'doh' }, { protocol: 'doh' }, { protocol: 'dot' }, { protocol: 'doq' }, { protocol: 'unknown' }
]), { doh: 2, dot: 1, doq: 1 }, 'simultaneous DNS protocols count independently');
assert.equal(ui.dnsServiceStateLabel('direct_ok'), 'DNS-ответ подтверждён · прямая проверка');
assert.equal(ui.dnsServiceStateLabel('bypass_ok'), 'DNS-ответ подтверждён · план прошёл DoH-проверку');
assert.equal(ui.dnsServiceStateLabel('plan_applied'), 'План применён · DNS-ответ ещё не подтверждён');
assert.equal(ui.dnsServiceStateLabel('failed'), 'DNS-ответ не получен');
assert.equal(ui.dnsServiceStateLabel('no_bypass'), 'Обход не найден');
assert.equal(ui.dnsServiceStateLabel('future-state'), 'Обнаружен · статус не измерен', 'unknown state stays conservative');
assert.equal(ui.dnsProtocolLabel('', 6, 443), '', 'ordinary HTTPS must not be guessed as DoH');
assert.equal(ui.dnsProtocolLabel('', 17, 443), '', 'ordinary QUIC must not be guessed as DoQ');
{
  const services = [
    { protocol: 'doh', host: 'cloudflare-dns.com', port: 443, source: 'https-dns-proxy', state: 'direct_ok' },
    { protocol: 'doh', host: 'dns.google', port: 443, source: 'https-dns-proxy' },
    { protocol: 'doh', host: 'dns.quad9.net', port: 443, source: 'https-dns-proxy' },
    { protocol: 'doh', host: 'dns.adguard-dns.com', port: 443, source: 'https-dns-proxy' },
    { protocol: 'dot', host: 'one.one.one.one', port: 853, source: 'dnsproxy', state: 'bypass_ok', status_reason: 'ответ DNS подтверждён на соединении с планом' },
    { protocol: 'dot', host: 'dns.google', port: 853, source: 'dnsproxy' },
    { protocol: 'dot', host: 'dns.quad9.net', port: 853, source: 'dnsproxy' },
    { protocol: 'dot', host: 'dns.adguard-dns.com', port: 853, source: 'dnsproxy' },
    { protocol: 'doq', host: 'dns.adguard-dns.com', port: 853, source: 'dnsproxy', state: 'failed', status_reason: 'тайм-аут DNS-запроса' },
    { protocol: 'doq', host: 'unfiltered.adguard-dns.com', port: 853, source: 'dnsproxy' },
  ];
  const m = ui.model({ snapshot: snap({ dns_services: services }), knowledge: { linked: true, searches: [
    { target: 'CLOUDFLARE-DNS.COM.', family: 4, transport: 6, ip: '1.1.1.1', port: 443 },
    { target: 'ordinary-cloudflare.example', family: 4, transport: 6, ip: '162.159.36.5', port: 443 },
    { target: 'dot.example', family: 4, transport: 6, ip: '192.0.2.10', port: 853 },
    { target: 'doq.example', family: 6, transport: 17, ip: '2001:db8::10', port: 853 },
  ] } });
  assert.deepEqual(m.dnsServices.map(s => [s.protocol, s.host, s.port, s.state]), services.map(s => [s.protocol, s.host, s.port, s.state || 'detected']));
  assert.deepEqual(m.dnsProtocolCounts, { doh: 4, dot: 4, doq: 2 });
  assert.equal(m.dnsServices[0].state, 'direct_ok');
  assert.equal(m.dnsServices[4].state, 'bypass_ok');
  assert.equal(m.dnsServices[4].status_reason, 'ответ DNS подтверждён на соединении с планом');
  assert.equal(m.dnsServices[8].state, 'failed');
  assert.equal(m.dnsServices[1].status_reason, 'Настройка найдена; проверка DNS-ответа ещё не выполнялась.');
  assert.deepEqual(services.map(s => ui.dnsProtocolLabel(s.protocol, s.protocol === 'doq' ? 17 : 6, s.port)),
    ['DoH', 'DoH', 'DoH', 'DoH', 'DoT', 'DoT', 'DoT', 'DoT', 'DoQ', 'DoQ']);
  assert.equal(ui.dnsProtocolLabel(m.searches[0].dns_protocol, 6, 443), '', 'a configured DoH hostname does not label an ordinary TLS search as DoH');
  assert.equal(ui.dnsProtocolLabel(m.searches[1].dns_protocol, 6, 443), '', 'Cloudflare IP alone must not classify a web target as DoH');
  assert.equal(ui.dnsProtocolLabel(m.searches[2].dns_protocol, 6, 853), 'DoT');
  assert.equal(ui.dnsProtocolLabel(m.searches[3].dns_protocol, 17, 853), 'DoQ');
  const live = ui.model({ snapshot: snap({ dns_services: [services[1]] }), knowledge: {
    linked: true, dns_services: [{ protocol: 'doh', host: 'dns.google', port: 443,
      state: 'direct_ok', resolved_ip: '8.8.8.8', dns_answer_confirmed: true,
      plan_applied: true, applied_plan_id: '00112233445566778899aabbccddeeff' }], searches: []
  } });
  assert.equal(live.dnsServices.length, 1);
  assert.equal(live.dnsServices[0].state, 'direct_ok', 'live autonomous DNS result wins over config-only snapshot');
  assert.equal(live.dnsServices[0].resolved_ip, '8.8.8.8');
  assert.equal(live.dnsServices[0].plan_applied, true);
  assert.equal(live.dnsServices[0].applied_plan_id, '00112233445566778899aabbccddeeff');
}

// Подтверждение семейства не зависит от установки общего правила.
{
  const g = { evidence_count: 5, evidence: ['a.googlevideo.com', 'b.googlevideo.com', 'c.googlevideo.com', 'd.googlevideo.com', 'e.googlevideo.com'],
    install_state: 'pending', install_reason: '' };
  assert.deepEqual(ui.familyStatus(g, true), {
    confirmation: 'Семейство подтверждено · 5 доменов',
    installation: 'Ожидает установки общего правила', active: false
  });
  assert.equal(ui.familyStatus({ ...g, install_state: 'active' }, true).installation, 'Общее правило активно');
  assert.equal(ui.familyStatus({ ...g, install_state: 'retrying', install_reason: 'ack_timeout' }, true).installation,
    'Повтор установки: датапат не ответил на ACK');
  assert.equal(ui.familyStatus({ ...g, install_state: 'retrying', install_reason: 'no_room' }, true).installation,
    'Повтор установки: в таблице датапата нет места');
  assert.equal(ui.familyStatus({ ...g, install_state: 'rejected', install_reason: 'bad_plan' }, true).installation,
    'Установка отклонена: план не принят датапатом: он не разбирается или не подходит способу отправки');
  assert.equal(ui.familyStatus({ ...g, install_state: 'rejected', install_reason: 'bad_args' }, true).installation,
    'Установка отклонена: датапат отклонил параметры команды');
  assert.equal(ui.familyStatus({ ...g, install_state: 'removing', remove_pending: true, possibly_active: true,
    exception_install_state: 'pending' }, true).installation,
  'Удаление общего правила ожидает ACK; правило может оставаться активным');
  assert.equal(ui.familyStatus({ ...g, install_state: 'retrying', install_reason: 'ack_timeout', remove_pending: true,
    possibly_active: true, exception_install_state: 'pending' }, true).installation,
  'Повтор удаления общего правила: датапат не ответил на ACK; правило может оставаться активным');
  assert.equal(ui.familyStatus({ ...g, install_state: 'pending', exception_install_state: 'retrying',
    exception_install_reason: 'no_room' }, true).installation,
  'Общее правило приостановлено; повтор установки исключения: в таблице датапата нет места');
  assert.equal(ui.familyStatus(g, false).installation, 'Нет связи с датапатом; статус установки неизвестен');
}

// Покрытие семейством: только активное семейство, тот же протокол/IP/путь, не исключение, только имена.
{
  const g = { suffix: 'example.com', active: true, transport: 6, family: 4, shape: 1, probe_path: '/', ech_origin: '',
    exceptions: [{ name: 'skip.example.com' }] };
  const b = (over) => ({ target: 'a.example.com', kind: 'name', transport: 6, family: 4, shape: 1, ...over });
  assert.equal(ui.coveredBy(b(), [g]), g);
  assert.equal(ui.coveredBy(b({ target: 'example.com.' }), [g]), g, 'trailing dot and apex match');
  assert.equal(ui.coveredBy(b({ target: 'notexample.com' }), [g]), null, 'suffix must match on a label boundary');
  assert.equal(ui.coveredBy(b({ target: 'skip.example.com' }), [g]), null, 'exceptions stay visible');
  assert.equal(ui.coveredBy(b({ family: 6 }), [g]), null, 'IPv6 is a different context');
  assert.equal(ui.coveredBy(b({ shape: 2 }), [g]), null, 'TLS 1.2 is a different context');
  assert.equal(ui.coveredBy(b({ transport: 17, shape: 3 }), [g]), null, 'QUIC is a different context');
  assert.equal(ui.coveredBy(b({ kind: 'addr', target: '1.2.3.4' }), [g]), null, 'addresses are never folded into names');
  assert.equal(ui.coveredBy(b(), [{ ...g, active: false }]), null, 'inactive family must not hide hosts');
  assert.equal(ui.coveredBy(b({ probe_path: '/x' }), [g]), null);
}

// Выжимка плана не показывает полезную нагрузку.
{
  const gist = ui.planGist('d2k-plan 1 1\nid 00\nproto tcp tls\npayload 1 0f0f0f0f\nsplit payload_start +1\norder reverse\n');
  assert.equal(gist, 'split payload_start +1 · order reverse');
}

assert.equal(ui.plural(1, 'поиск', 'поиска', 'поисков'), 'поиск');
assert.equal(ui.plural(3, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.plural(11, 'поиск', 'поиска', 'поисков'), 'поисков');
assert.equal(ui.plural(22, 'поиск', 'поиска', 'поисков'), 'поиска');
assert.equal(ui.duration(3725000), '1 ч 2 мин');
assert.equal(ui.telegramRouteName(1), 'Маршрут не определён');
assert.equal(ui.telegramRouteName(2), 'Cloudflare Worker');
assert.equal(ui.telegramRouteName(3), 'Прокси Cloudflare');
assert.equal(ui.telegramRouteName(4), 'Маршрут не определён');
assert.equal(ui.telegramFailureStage(5), 'MTProto');

// Предел замеров — живой, от 1 до десятков: клетки до 16, дальше шкала; подпись честно говорит, откуда предел.
{
  const weak = ui.slotsView({ active: 1, limit: 1, queued: 3, free_pct: 12, cores: 1 });
  assert.equal(weak.kind, 'cells'); assert.equal(weak.limit, 1); assert.equal(weak.queued, 3);
  assert.equal(weak.short, 'предел по нагрузке роутера');
  const strong = ui.slotsView({ active: 23, limit: 40, queued: 0, free_pct: 80, cores: 4 });
  assert.equal(strong.kind, 'bar', 'dozens of slots are shown as a share, not as 16 capped cells');
  assert.equal(strong.limit, 40);
  const blind = ui.slotsView({ active: 0, limit: 2, queued: 0, free_pct: null, cores: null });
  assert.equal(blind.short, 'предел по умолчанию');
  assert.match(blind.note, /Данных о нагрузке/);
}
console.log('panel model: all checks passed');
