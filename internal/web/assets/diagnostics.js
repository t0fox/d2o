/* Локальная история отключена по умолчанию и никуда не отправляется. */
(function (root) {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var metrics = [
    { key: "rss", label: "RSS", color: "rss" },
    { key: "vm_data", label: "VmData", color: "vm_data" },
    { key: "anonymous", label: "Anonymous", color: "anonymous" },
    { key: "private_dirty", label: "Private_Dirty", color: "private_dirty" }
  ];
  var reasons = {
    cpu: "CPU", memory: "память", conntrack: "conntrack", slots: "слоты",
    "resource-data-unavailable": "ресурсные данные недоступны",
    "no-current-resource-limit": "текущих ограничений нет"
  };
  function list(value) { return Array.isArray(value) ? value : []; }
  function number(value) { return typeof value === "number" && isFinite(value) ? value : null; }
  function pretty(value) { return value === null ? "—" : String(value); }
  function formatBytes(bytes) {
    if (number(bytes) === null || bytes < 0) return "—";
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " МиБ";
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " КиБ";
    return Math.round(bytes) + " Б";
  }
  function formatKib(kib) { return number(kib) === null ? "—" : (kib / 1024).toFixed(1) + " МиБ"; }
  function formatAge(ms) {
    if (number(ms) === null || ms < 0) return "—";
    if (ms < 1000) return Math.round(ms) + " мс";
    if (ms < 60000) return Math.floor(ms / 1000) + " с";
    return Math.floor(ms / 60000) + " мин " + String(Math.floor(ms / 1000) % 60).padStart(2, "0") + " с";
  }
  function intervalText(ms) {
    if (number(ms) === null || ms <= 0) return "Интервал указан в отчёте · значения в МиБ";
    if (ms % 60000 === 0) return "Снимок раз в " + (ms / 60000) + " мин · значения в МиБ";
    if (ms % 1000 === 0) return "Снимок раз в " + (ms / 1000) + " с · значения в МиБ";
    return "Снимок раз в " + ms + " мс · значения в МиБ";
  }
  function sampleWord(count) { return count % 10 === 1 && count % 100 !== 11 ? "снимке" : "снимках"; }
  function countWithCapacity(count, capacity) {
    return number(capacity) !== null && capacity > 0 ? count + " / " + capacity : String(count);
  }
  function firstDefined(listOfValues) {
    for (var i = 0; i < listOfValues.length; i++) if (number(listOfValues[i]) !== null) return listOfValues[i];
    return null;
  }
  function detailsFor(report) {
    return list(report.memory_details).filter(function (item) { return item && item.name === "d2kc"; })[0] || null;
  }
  function sumGroups(smaps, field) {
    if (!smaps) return null;
    var groups = ["anonymous", "heap", "stack", "other"], total = 0, seen = false;
    groups.forEach(function (group) {
      var value = smaps[group] && number(smaps[group][field]);
      if (value !== null) { total += value; seen = true; }
    });
    return seen ? total : null;
  }
  function memoryRows(report) {
    var memory = report.memory_history;
    if (memory && list(memory.samples).length) {
      var base = list(memory.time_base), epoch = number(base[0]) || 0, mono = number(base[1]) || 0;
      return memory.samples.map(function (row) {
        if (!Array.isArray(row)) return null;
        var rollup = Array.isArray(row[7]) ? row[7] : [];
        return {
          at: epoch + (number(row[0]) || 0), time: mono + (number(row[1]) || 0),
          rss: number(row[2]), vm_data: number(row[3]), status: number(row[5]), errno: number(row[6]),
          anonymous: row[5] === 2 ? number(rollup[2]) : null,
          private_dirty: row[5] === 2 ? number(rollup[3]) : null
        };
      }).filter(Boolean);
    }
    var rows = list(report.samples).map(function (sample) {
      var proc = list(sample && sample.processes).filter(function (item) { return item && item.name === "d2kc"; })[0] || {};
      return {
        at: number(sample && sample.at),
        time: number(sample && sample.mono_ms) === null ? number(sample && sample.at) : sample.mono_ms / 1000,
        rss: number(proc.rss_kib), vm_data: number(proc.vm_data_kib), anonymous: number(proc.anon_kib),
        private_dirty: null, status: null, errno: null
      };
    });
    var detail = detailsFor(report), latest = detail && detail.latest;
    if (latest && rows.length) {
      var final = rows[rows.length - 1], rollup = latest.smaps_rollup;
      final.vm_data = firstDefined([latest.vm_data_kib, final.vm_data]);
      if (rollup) {
        final.rss = firstDefined([rollup.rss_kib, final.rss]);
        final.anonymous = number(rollup.anonymous_kib);
        final.private_dirty = number(rollup.private_dirty_kib);
      } else if (latest.smaps) {
        final.anonymous = sumGroups(latest.smaps, "anonymous_kib");
        final.private_dirty = sumGroups(latest.smaps, "private_dirty_kib");
      }
      if (latest.smaps_rollup_status === "unavailable") final.status = 1;
      else if (latest.smaps_rollup_status === "parse-error") final.status = 3;
      final.errno = number(latest.smaps_rollup_errno);
    }
    return rows;
  }
  function rowsInRange(rows, hours) {
    if (!rows.length) return [];
    var last = rows[rows.length - 1].time;
    if (number(last) === null) return rows.slice(-Math.ceil(hours * 60));
    var start = last - hours * 3600;
    return rows.filter(function (row) { return number(row.time) === null || row.time >= start; });
  }
  function svg(doc, name, attrs) {
    var node = doc.createElementNS(SVG, name);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    return node;
  }
  function timeLabel(seconds) {
    if (number(seconds) === null || seconds <= 0) return "—";
    return new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function drawMemory(doc, report, hours) {
    var chart = doc.getElementById("diagnostic-memory-chart"), empty = doc.getElementById("diagnostic-memory-empty");
    if (!chart || !empty) return { rows: [], delta: null };
    var rows = rowsInRange(memoryRows(report), hours);
    var options = {}, available = {};
    metrics.forEach(function (metric) {
      var input = doc.querySelector('[data-memory-series="' + metric.key + '"]');
      var values = rows.map(function (row) { return row[metric.key]; }).filter(function (value) { return number(value) !== null; });
      available[metric.key] = values.length > 0;
      if (input) {
        input.parentNode.hidden = !available[metric.key];
        options[metric.key] = input.checked;
        var valueNode = input.parentNode.querySelector("small");
        if (!valueNode) { valueNode = doc.createElement("small"); input.parentNode.appendChild(valueNode); }
        var first = values.length ? values[0] : null, latest = values.length ? values[values.length - 1] : null;
        valueNode.textContent = latest === null ? "—" : formatKib(latest) + (first === null ? "" : " · " + (latest - first >= 0 ? "+" : "") + formatKib(latest - first));
      }
    });
    var active = metrics.filter(function (metric) { return available[metric.key] && options[metric.key]; });
    var all = [];
    active.forEach(function (metric) { rows.forEach(function (row) { if (number(row[metric.key]) !== null) all.push(row[metric.key]); }); });
    chart.replaceChildren();
    chart.dataset.points = String(rows.length);
    chart.setAttribute("aria-label", "Память d2kc, период " + hours + " часа, точек: " + rows.length);
    if (!rows.length || !active.length || !all.length) {
      chart.hidden = true;
      empty.hidden = false;
      empty.textContent = !active.length && rows.length ? "Выберите доступный показатель памяти." : "Для выбранного периода нет доступных снимков памяти.";
      return { rows: rows, delta: null };
    }
    chart.hidden = false; empty.hidden = true;
    var left = 68, right = 948, top = 16, bottom = 218;
    var min = Math.min.apply(Math, all), max = Math.max.apply(Math, all);
    if (min === max) { var pad = Math.max(min * .08, 128); min = Math.max(0, min - pad); max += pad; }
    else { var margin = (max - min) * .08; min = Math.max(0, min - margin); max += margin; }
    for (var tick = 0; tick <= 4; tick++) {
      var y = top + (bottom - top) * tick / 4;
      chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: y, y2: y, "class": "diag-gridline" }));
      var label = svg(doc, "text", { x: left - 8, y: y + 4, "text-anchor": "end" });
      label.textContent = ((max - (max - min) * tick / 4) / 1024).toFixed(0);
      chart.appendChild(label);
    }
    chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: bottom, y2: bottom, "class": "diag-axis" }));
    var firstTime = number(rows[0].time), lastTime = number(rows[rows.length - 1].time);
    var xLabelStart = svg(doc, "text", { x: left, y: 248, "text-anchor": "start" });
    var xLabelEnd = svg(doc, "text", { x: right, y: 248, "text-anchor": "end" });
    xLabelStart.textContent = timeLabel(rows[0].at || firstTime);
    xLabelEnd.textContent = timeLabel(rows[rows.length - 1].at || lastTime);
    chart.appendChild(xLabelStart); chart.appendChild(xLabelEnd);
    active.forEach(function (metric) {
      var commands = [], seen = 0, segment = false;
      rows.forEach(function (row, index) {
        var value = number(row[metric.key]);
        if (value === null) { segment = false; return; }
        var x = rows.length < 2 ? (left + right) / 2 : left + (right - left) * index / (rows.length - 1);
        var y = bottom - (bottom - top) * (value - min) / (max - min);
        commands.push((segment ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1));
        segment = true;
        seen++;
      });
      if (seen > 0) chart.appendChild(svg(doc, "path", { d: commands.join(" "), "class": "diag-line diag-line-" + metric.color, "data-series": metric.key }));
    });
    var rss = rows.map(function (row) { return row.rss; }).filter(function (value) { return number(value) !== null; });
    return { rows: rows, delta: rss.length > 1 ? rss[rss.length - 1] - rss[0] : null };
  }
  function processRows(doc, samples) {
    var body = doc.getElementById("diagnostic-processes");
    if (!body) return;
    body.replaceChildren();
    var labels = { d2kc: "Контроллер", d2kd: "Датапат", d2kpanel: "Панель" };
    var last = samples[samples.length - 1];
    if (!last || !list(last.processes).length) {
      var empty = doc.createElement("tr"), cell = doc.createElement("td"); cell.colSpan = 3; cell.textContent = "Данные процессов недоступны."; empty.appendChild(cell); body.appendChild(empty); return;
    }
    list(last.processes).forEach(function (proc) {
      var first = null;
      samples.some(function (sample) {
        first = list(sample.processes).filter(function (item) { return item.name === proc.name && item.pid === proc.pid && number(item.rss_kib) !== null; })[0] || null;
        return !!first;
      });
      var known = number(proc.rss_kib), delta = known !== null && first && number(first.rss_kib) !== null ? (known - first.rss_kib) / 1024 : null;
      var row = doc.createElement("tr"), name = doc.createElement("td"), code = doc.createElement("small");
      name.textContent = labels[proc.name] || proc.name; code.textContent = proc.name; name.appendChild(code); row.appendChild(name);
      [known === null ? "—" : (known / 1024).toFixed(1), delta === null ? "—" : (delta > 0 ? "+" : "") + delta.toFixed(1)].forEach(function (value) {
        var item = doc.createElement("td"); item.textContent = value; row.appendChild(item);
      });
      body.appendChild(row);
    });
  }
  function reasonText(values) {
    return list(values).map(function (value) { return reasons[value] || value; }).join(", ") || "причина не указана";
  }
  function renderAimd(doc, report, last) {
    var current = doc.getElementById("diagnostic-aimd-current"), history = doc.getElementById("diagnostic-aimd-history");
    if (!current || !history) return;
    if (last && number(last.measurement_limit) !== null && number(last.measurement_slots) !== null) {
      current.textContent = "Текущий лимит " + last.measurement_limit + "/" + last.measurement_slots + " · " + reasonText(last.limit_reason) +
        (last.grow_pending ? " · увеличение ожидает следующего измерения" : "");
    } else current.textContent = "Текущий лимит не записан в этом отчёте.";
    history.replaceChildren();
    var transitions = list(report.limit_transitions).slice().reverse();
    if (!transitions.length) {
      var empty = doc.createElement("li"); empty.className = "diag-transition-empty";
      empty.textContent = report.limit_transitions ? "Переходов за сохранённый период нет." : "История переходов отсутствует в старом отчёте.";
      history.appendChild(empty); return;
    }
    transitions.forEach(function (item) {
      var row = doc.createElement("li"), strong = doc.createElement("strong"), label = doc.createElement("span"), time = doc.createElement("small");
      strong.textContent = pretty(number(item.measurement_limit)) + " / " + pretty(number(item.measurement_slots));
      label.textContent = reasonText(item.limit_reason);
      time.textContent = number(item.at) === null ? "" : new Date(item.at * 1000).toLocaleString();
      row.appendChild(strong); row.appendChild(label); row.appendChild(time); history.appendChild(row);
    });
  }
  function renderWarnings(doc, report, chart, hours) {
    var box = doc.getElementById("diagnostic-warnings");
    if (!box) return;
    box.replaceChildren();
    var warnings = [], delta = chart.delta;
    if (number(delta) !== null && delta > 0) warnings.push("RSS d2kc вырос на " + formatKib(delta) + " за выбранные " + hours + " часа; рост сам по себе не подтверждает утечку.");
    var lost = [
      ["events_overwritten", "записи завершений"], ["samples_overwritten", "минутные снимки"],
      ["memory_history_overwritten", "снимки памяти"], ["limit_transitions_overwritten", "переходы AIMD"]
    ].map(function (entry) { return { key: entry[0], label: entry[1], count: number(report[entry[0]]) }; })
      .filter(function (entry) { return entry.count !== null && entry.count > 0; });
    if (lost.length) warnings.push("Кольцевые журналы вытеснили записи: " + lost.map(function (entry) { return entry.label + " — " + entry.count; }).join(", ") + ".");
    var rows = memoryRows(report), unavailable = rows.filter(function (row) { return row.status === 1; }).length;
    var parseErrors = rows.filter(function (row) { return row.status === 3; }).length;
    var detail = detailsFor(report), latest = detail && detail.latest;
    if (!unavailable && latest && latest.smaps_rollup_status === "unavailable") unavailable = 1;
    if (!parseErrors && latest && latest.smaps_rollup_status === "parse-error") parseErrors = 1;
    var errno = rows.slice().reverse().filter(function (row) { return row.status === 1 && row.errno; })[0];
    if (unavailable) warnings.push("smaps_rollup недоступен в " + unavailable + " " + sampleWord(unavailable) + (errno ? " (errno " + errno.errno + ")" : "") + ".");
    if (parseErrors) warnings.push("smaps_rollup не удалось разобрать в " + parseErrors + " " + sampleWord(parseErrors) + ".");
    warnings.forEach(function (warning) { var p = doc.createElement("p"); p.textContent = warning; box.appendChild(p); });
    box.hidden = warnings.length === 0;
  }
  function setText(doc, id, value) {
    var node = doc.getElementById(id); if (node) node.textContent = value;
  }
  function overflowText(last) {
    var names = [
      ["http_record_limit_hits", "записи"], ["http_queue_limit_hits", "очередь"],
      ["http_failure_limit_hits", "общие ошибки"], ["http_failure_record_limit_hits", "ошибки на сайт"]
    ];
    var known = 0, hits = [];
    names.forEach(function (entry) {
      var count = number(last[entry[0]]);
      if (count !== null) { known++; if (count) hits.push(entry[1] + " — " + count); }
    });
    return !known ? "—" : hits.length ? hits.join(" · ") : "нет";
  }
  function storageRow(used, limit) {
    return formatBytes(used) + (number(limit) !== null && limit > 0 ? " / " + formatBytes(limit) : "");
  }
  function render(report, enabled, range) {
    var doc = root.document, samples = list(report.samples), events = list(report.events), last = samples[samples.length - 1];
    var httpLimits = report.http_storage_limits || {};
    var state = doc.getElementById("diagnostic-state"), data = doc.getElementById("diagnostic-data");
    state.textContent = enabled ? "Сбор включён" : "Сбор выключен";
    state.dataset.enabled = String(enabled);
    data.hidden = !enabled;
    if (!enabled) { doc.getElementById("diagnostic-status").textContent = "Сбор выключен. Включите его, чтобы записать память и исходы поиска."; return; }
    var mem = report.memory_history, memorySamples = list(mem && mem.samples);
    setText(doc, "diagnostic-memory-interval", intervalText(number(mem && mem.sample_interval_ms) || number(report.sample_interval_ms)));
    if (!last && !memorySamples.length) {
      doc.getElementById("diagnostic-status").textContent = report.pending ? "Отчёт формируется. Ожидаем первый снимок." : "Ожидаем первый снимок. Отчёт обновляется по мере работы контроллера.";
    } else {
      var latestAt = last && number(last.at);
      if (latestAt === null && memorySamples.length && list(mem.time_base).length) latestAt = (number(mem.time_base[0]) || 0) + (number(memorySamples[memorySamples.length - 1][0]) || 0);
      doc.getElementById("diagnostic-status").textContent = latestAt === null ? "История диагностики загружена." : "Обновлено " + new Date(latestAt * 1000).toLocaleTimeString() +
        (number(report.sample_interval_ms) !== null ? " · интервал " + formatAge(report.sample_interval_ms) : "");
    }
    processRows(doc, samples);
    setText(doc, "diagnostic-events", countWithCapacity(events.length, report.event_capacity));
    setText(doc, "diagnostic-unconfirmed", String(events.filter(function (event) { return ["failed", "inconclusive", "unknown", "local-abort", "queue-full"].indexOf(event.outcome) >= 0; }).length));
    setText(doc, "diagnostic-samples", countWithCapacity(samples.length, report.sample_capacity) + (memorySamples.length ? " · память: " + countWithCapacity(memorySamples.length, mem.capacity) : ""));
    setText(doc, "diagnostic-workers-running", pretty(number(last && last.workers_running)));
    setText(doc, "diagnostic-workers-result", pretty(number(last && last.workers_result_pending)));
    setText(doc, "diagnostic-workers-join", pretty(number(last && last.workers_join_pending)));
    setText(doc, "diagnostic-workers-oldest", last && number(last.worker_oldest_age_ms) !== null ? formatAge(last.worker_oldest_age_ms) + (last.worker_oldest_type ? " · " + last.worker_oldest_type : "") : "—");
    setText(doc, "diagnostic-workers-errors", last && (number(last.worker_start_failures) !== null || number(last.worker_join_failures) !== null) ?
      pretty(number(last.worker_start_failures)) + " / " + pretty(number(last.worker_join_failures)) : "—");
    setText(doc, "diagnostic-catalog-bytes", formatBytes(last && last.catalog_bytes));
    setText(doc, "diagnostic-snapshot-bytes", formatBytes(last && last.snapshot_bytes));
    setText(doc, "diagnostic-catalog-counts", last ? [last.boxes, last.bindings, last.plans].map(function (value) { return number(value) === null ? "—" : value; }).join(" / ") : "—");
    setText(doc, "diagnostic-http-bytes", formatBytes(last && last.http_bytes));
    setText(doc, "diagnostic-http-records", last ? storageRow(last.http_records_bytes, firstDefined([last.http_records_limit_bytes, httpLimits.records_bytes])) : "—");
    setText(doc, "diagnostic-http-queue", last ? storageRow(last.http_queue_bytes, firstDefined([last.http_queue_limit_bytes, httpLimits.queue_bytes])) : "—");
    setText(doc, "diagnostic-http-evidence", last ? storageRow(last.http_failure_bytes, firstDefined([last.http_failure_limit_bytes, httpLimits.failures_bytes])) +
      (firstDefined([last.http_failure_record_limit_bytes, httpLimits.failure_record_bytes]) !== null ? " · до " + formatBytes(firstDefined([last.http_failure_record_limit_bytes, httpLimits.failure_record_bytes])) + " на сайт" : "") : "—");
    setText(doc, "diagnostic-http-overflows", last ? overflowText(last) : "—");
    renderAimd(doc, report, last);
    var chart = drawMemory(doc, report, range);
    renderWarnings(doc, report, chart, range);
  }
  function summary(report) {
    var samples = list(report && report.samples), events = list(report && report.events), last = samples[samples.length - 1];
    if (!last && !list(report && report.memory_history && report.memory_history.samples).length) return "Сбор включён. Ожидаем первый снимок контроллера.";
    var rss = list(last && last.processes).filter(function (p) { return p.name === "d2kc" && number(p.rss_kib) !== null; })[0];
    var first = null;
    if (rss) samples.some(function (sample) {
      first = list(sample.processes).filter(function (p) { return p.name === rss.name && p.pid === rss.pid && number(p.rss_kib) !== null; })[0] || null;
      return !!first;
    });
    var failures = events.filter(function (event) { return ["failed", "inconclusive", "unknown", "local-abort", "queue-full"].indexOf(event.outcome) >= 0; }).length;
    var memory = report.memory_history || {}, detail = detailsFor(report);
    return "Снимков: " + countWithCapacity(samples.length, report.sample_capacity) + "; завершений поиска: " + countWithCapacity(events.length, report.event_capacity) +
      ", без подтверждённого результата: " + failures + ". " + (rss ? "RSS d2kc: " + formatKib(rss.rss_kib) +
      (first ? " (" + ((rss.rss_kib - first.rss_kib) >= 0 ? "+" : "") + ((rss.rss_kib - first.rss_kib) / 1024).toFixed(1) + " за историю этого PID)" : "") + ". " : "") +
      "Снимков памяти: " + countWithCapacity(list(memory.samples).length, memory.capacity) +
      (detail && detail.latest && detail.latest.smaps_rollup_status === "unavailable" ? ". smaps_rollup недоступен." : "");
  }
  if (typeof module === "object" && module.exports) module.exports = { summary: summary };
  if (!root.document || !root.fetch) return;
  function boot() {
    var doc = root.document, toggle = doc.getElementById("diagnostic-toggle"), status = doc.getElementById("diagnostic-status"), download = doc.getElementById("diagnostic-download");
    if (!toggle || !status || !download) return;
    var enabled = false, busy = false, range = 2, currentReport = {};
    function redraw() { render(currentReport, enabled, range); }
    doc.querySelectorAll("[data-memory-range]").forEach(function (button) {
      button.addEventListener("click", function () {
        range = Number(button.dataset.memoryRange);
        doc.querySelectorAll("[data-memory-range]").forEach(function (item) { item.setAttribute("aria-pressed", String(item === button)); });
        redraw();
      });
    });
    doc.querySelectorAll("[data-memory-series]").forEach(function (input) { input.addEventListener("change", redraw); });
    function refresh() {
      return root.fetch("/api/diagnostics?report", { cache: "no-store" }).then(function (r) {
        if (!r.ok && r.status !== 503) throw new Error("Ошибка HTTP " + r.status);
        return r.json();
      }).then(function (r) {
        currentReport = r || {}; enabled = currentReport.enabled === true;
        toggle.textContent = enabled ? "Выключить и удалить историю" : "Включить сбор";
        download.hidden = !enabled || !!currentReport.pending;
        redraw();
      }).catch(function () { status.textContent = "Не удалось прочитать состояние диагностики."; });
    }
    toggle.addEventListener("click", function () {
      if (busy) return; busy = true; toggle.disabled = true;
      root.fetch("/api/diagnostics?" + (enabled ? "disable" : "enable"), { method: "POST", cache: "no-store" }).then(function (r) {
        if (!r.ok) throw new Error("Ошибка HTTP " + r.status);
        return refresh();
      }).catch(function () { status.textContent = "Не удалось переключить сбор. Требуется доступ к управлению этой панелью."; })
        .finally(function () { busy = false; toggle.disabled = false; });
    });
    refresh(); root.setInterval(function () { if (!busy && !doc.hidden) refresh(); }, 60000);
  }
  if (root.document.readyState === "loading") root.document.addEventListener("DOMContentLoaded", boot); else boot();
})(typeof window !== "undefined" ? window : this);
