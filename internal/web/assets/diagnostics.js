/* Локальная история отключена по умолчанию и никуда не отправляется. */
(function (root) {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var metrics = [
    { key: "rss", label: "RSS", color: "rss" },
    { key: "rss_anon", label: "RssAnon", color: "rss_anon" },
    { key: "vm_data", label: "VmData", color: "vm_data" },
    { key: "anonymous", label: "Anonymous", color: "anonymous" },
    { key: "private_dirty", label: "Private_Dirty", color: "private_dirty" },
    { key: "catalog", label: "Каталог", color: "catalog" },
    { key: "http", label: "HTTP", color: "http" },
    { key: "snapshot", label: "Снимки", color: "snapshot" },
    { key: "tracked_tcp", label: "TCP", color: "tracked_tcp" },
    { key: "tracked_quic", label: "QUIC", color: "tracked_quic" },
    { key: "tracked_tls", label: "TLS", color: "tracked_tls" }
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
  function formatKib(kib) { return number(kib) === null ? "—" : formatBytes(kib * 1024); }
  function formatDeltaBytes(bytes) {
    if (number(bytes) === null) return "—";
    return (bytes > 0 ? "+" : bytes < 0 ? "−" : "") + formatBytes(Math.abs(bytes));
  }
  function kibBytes(kib) { return number(kib) === null ? null : kib * 1024; }
  function formatAge(ms) {
    if (number(ms) === null || ms < 0) return "—";
    if (ms < 1000) return Math.round(ms) + " мс";
    if (ms < 60000) return Math.floor(ms / 1000) + " с";
    return Math.floor(ms / 60000) + " мин " + String(Math.floor(ms / 1000) % 60).padStart(2, "0") + " с";
  }
  function intervalText(ms, axisUnit) {
    var interval = number(ms) === null || ms <= 0 ? "Интервал указан в отчёте" :
      ms % 60000 === 0 ? "Снимок раз в " + (ms / 60000) + " мин" :
      ms % 1000 === 0 ? "Снимок раз в " + (ms / 1000) + " с" : "Снимок раз в " + ms + " мс";
    return interval + (axisUnit ? " · ось в " + axisUnit : " · значения подписаны своими единицами");
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
  function sampleTime(sample) {
    var mono = number(sample && sample.mono_ms);
    return mono === null ? number(sample && sample.at) : mono / 1000;
  }
  function memoryField(memory, row, key, legacyIndex) {
    var fields = list(memory && memory.fields);
    if (fields.length) {
      var index = fields.indexOf(key);
      return index < 0 ? null : number(row[index]);
    }
    return number(row[legacyIndex]);
  }
  function memoryBytesField(memory, row, bytesKey, kibKey, legacyIndex) {
    var fields = list(memory && memory.fields);
    if (fields.length) {
      var bytesIndex = fields.indexOf(bytesKey);
      if (bytesIndex >= 0) return number(row[bytesIndex]);
      var kibIndex = fields.indexOf(kibKey);
      return kibIndex < 0 ? null : kibBytes(number(row[kibIndex]));
    }
    return kibBytes(number(row[legacyIndex]));
  }
  function sampleForHistoryRow(report, at, time, domain) {
    var nearest = null, distance = Infinity;
    list(report.samples).forEach(function (sample) {
      var sampleMono = number(sample && sample.mono_ms), candidateAt = number(sample && sample.at);
      var d = domain === "mono" && sampleMono !== null && number(time) !== null ? Math.abs(sampleMono / 1000 - time) :
        number(at) !== null && candidateAt !== null ? Math.abs(candidateAt - at) : Infinity;
      if (d <= 1 && d < distance) { nearest = sample; distance = d; }
    });
    return nearest;
  }
  function generationForSample(report, at, time, domain) {
    var sample = sampleForHistoryRow(report, at, time, domain);
    var proc = sample && list(sample.processes).filter(function (item) { return item && item.name === "d2kc"; })[0];
    return proc && number(proc.pid) !== null ? proc.pid : null;
  }
  function memoryRows(report) {
    var memory = report.memory_history, history = list(memory && memory.samples);
    if (history.length) {
      var base = list(memory.time_base), wallBase = number(base[0]), monoBase = number(base[1]);
      return history.map(function (row) {
        if (!Array.isArray(row)) return null;
        var atDelta = memoryField(memory, row, "at_delta_s", 0);
        var monoDelta = memoryField(memory, row, "mono_delta_s", 1);
        var at = wallBase === null || atDelta === null ? null : wallBase + atDelta;
        var timeDomain = monoBase !== null && monoDelta !== null ? "mono" : "wall";
        var time = timeDomain === "mono" ? monoBase + monoDelta : at;
        var rollupIndex = list(memory.fields).length ? list(memory.fields).indexOf("smaps_rollup_kib") : 7;
        var rollup = rollupIndex < 0 || !Array.isArray(row[rollupIndex]) ? [] : row[rollupIndex];
        var epoch = memoryField(memory, row, "d2kc_epoch", -1);
        var result = {
          at: at, time: time, time_domain: timeDomain, generation: epoch,
          rss: kibBytes(memoryField(memory, row, "rss_kib", 2)),
          vm_data: kibBytes(memoryField(memory, row, "vm_data_kib", 3)),
          vm_swap: kibBytes(memoryField(memory, row, "vm_swap_kib", 4)),
          status: memoryField(memory, row, "smaps_rollup_status_code", 5),
          errno: memoryField(memory, row, "smaps_rollup_errno", 6),
          rss_anon: kibBytes(memoryField(memory, row, "rss_anon_kib", 8)),
          catalog: memoryBytesField(memory, row, "catalog_bytes", "catalog_kib", 9),
          http: memoryBytesField(memory, row, "http_bytes", "http_kib", 10),
          snapshot: memoryBytesField(memory, row, "snapshot_bytes", "snapshot_kib", 11),
          tracked_tcp: memoryBytesField(memory, row, "tracked_tcp_bytes", "tracked_tcp_kib", 12),
          tracked_quic: memoryBytesField(memory, row, "tracked_quic_bytes", "tracked_quic_kib", 13),
          tracked_tls: memoryBytesField(memory, row, "tracked_tls_bytes", "tracked_tls_kib", 14),
          tasks: memoryField(memory, row, "tasks", 15), workers_live: memoryField(memory, row, "workers_live", 16),
          workers_result_pending: memoryField(memory, row, "workers_result_pending", 17),
          workers_join_pending: memoryField(memory, row, "workers_join_pending", 18),
          anonymous: kibBytes(number(rollup[2])), private_dirty: kibBytes(number(rollup[3]))
        };
        var sample = sampleForHistoryRow(report, at, time, timeDomain), fields = list(memory.fields);
        if (epoch === null) result.generation = generationForSample(report, at, time, timeDomain);
        if (sample && (!fields.length || fields.indexOf("catalog_bytes") < 0)) result.catalog = number(sample.catalog_bytes) === null ? result.catalog : sample.catalog_bytes;
        if (sample && (!fields.length || fields.indexOf("http_bytes") < 0)) result.http = number(sample.http_bytes) === null ? result.http : sample.http_bytes;
        if (sample && (!fields.length || fields.indexOf("snapshot_bytes") < 0)) result.snapshot = number(sample.snapshot_bytes) === null ? result.snapshot : sample.snapshot_bytes;
        return result;
      }).filter(Boolean);
    }
    var rows = list(report.samples).map(function (sample) {
      var proc = list(sample && sample.processes).filter(function (item) { return item && item.name === "d2kc"; })[0] || {};
      return {
        at: number(sample && sample.at), time: sampleTime(sample), time_domain: number(sample && sample.mono_ms) === null ? "wall" : "mono", generation: number(proc.pid),
        rss: kibBytes(number(proc.rss_kib)), rss_anon: kibBytes(number(proc.anon_kib)),
        vm_data: kibBytes(number(proc.vm_data_kib)), anonymous: null, private_dirty: null,
        catalog: number(sample && sample.catalog_bytes), http: number(sample && sample.http_bytes),
        snapshot: number(sample && sample.snapshot_bytes), tracked_tcp: null, tracked_quic: null, tracked_tls: null,
        status: null, errno: null
      };
    });
    var detail = detailsFor(report), latest = detail && detail.latest;
    if (latest && rows.length) {
      var final = rows[rows.length - 1], rollup = latest.smaps_rollup;
      final.vm_data = firstDefined([latest.vm_data_kib, final.vm_data]);
      if (rollup) {
        final.rss = firstDefined([kibBytes(number(rollup.rss_kib)), final.rss]);
        final.anonymous = kibBytes(number(rollup.anonymous_kib));
        final.private_dirty = kibBytes(number(rollup.private_dirty_kib));
      } else if (latest.smaps) {
        final.anonymous = kibBytes(sumGroups(latest.smaps, "anonymous_kib"));
        final.private_dirty = kibBytes(sumGroups(latest.smaps, "private_dirty_kib"));
      }
      if (latest.smaps_rollup_status === "unavailable") final.status = 1;
      else if (latest.smaps_rollup_status === "parse-error") final.status = 3;
      else if (latest.smaps_rollup_status === "unsupported") final.status = 4;
      final.errno = number(latest.smaps_rollup_errno);
    }
    return rows;
  }
  function rowsInRange(rows, hours, intervalMs) {
    if (!rows.length) return [];
    var timed = rows.filter(function (row) { return number(row.time) !== null; });
    if (!timed.length) return rows.slice(-Math.ceil(hours * 3600000 / (number(intervalMs) || 60000)));
    var last = timed[timed.length - 1].time;
    var start = last - hours * 3600;
    return timed.filter(function (row) { return row.time >= start; });
  }
  function seriesEndpoints(rows, key) {
    var end = null;
    for (var i = rows.length - 1; i >= 0; i--) if (number(rows[i][key]) !== null) { end = rows[i]; break; }
    if (!end) return { first: null, last: null, delta: null };
    if (key === "rss" && number(end.generation) === null) return { first: end, last: end, delta: null };
    var first = null, count = 0;
    for (var j = 0; j < rows.length; j++) {
      if (key === "rss" && end.generation !== null && number(end.generation) !== null && rows[j].generation !== end.generation) continue;
      if (number(rows[j][key]) !== null) { if (!first) first = rows[j]; count++; }
    }
    return { first: first, last: end, delta: count > 1 ? end[key] - first[key] : null };
  }
  function durationText(seconds) {
    if (number(seconds) === null || seconds < 60) return "менее минуты";
    var minutes = Math.floor(seconds / 60), hours = Math.floor(minutes / 60), days = Math.floor(hours / 24);
    if (days) return days + " д " + (hours % 24) + " ч";
    if (hours) return hours + " ч " + (minutes % 60) + " мин";
    return minutes + " мин";
  }
  function rangeText(hours) { return hours === 2 || hours === 24 ? hours + " часа" : hours + " часов"; }
  function coverageText(rows, hours) {
    if (!rows.length) return "Доступно 0 снимков из " + rangeText(hours) + ".";
    var timed = rows.filter(function (row) { return number(row.time) !== null; });
    if (!timed.length) return "Время снимков отсутствует · точек: " + rows.length + ".";
    var span = Math.max(0, timed[timed.length - 1].time - timed[0].time);
    return "Доступно " + durationText(span) + " из " + rangeText(hours) + " · снимков: " + rows.length + ".";
  }
  function svg(doc, name, attrs) {
    var node = doc.createElementNS(SVG, name);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    return node;
  }
  function timeLabel(seconds) {
    if (number(seconds) === null) return "—";
    return new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function drawMemory(doc, allRows, hours, intervalMs) {
    var chart = doc.getElementById("diagnostic-memory-chart"), empty = doc.getElementById("diagnostic-memory-empty");
    if (!chart || !empty) return { rows: [], delta: null, axisUnit: null };
    var rows = rowsInRange(allRows, hours, intervalMs);
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
        var endpoints = seriesEndpoints(rows, metric.key);
        valueNode.textContent = endpoints.last === null ? "—" : formatBytes(endpoints.last[metric.key]) +
          (endpoints.delta === null ? "" : " · " + formatDeltaBytes(endpoints.delta));
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
      return { rows: rows, delta: null, axisUnit: null };
    }
    chart.hidden = false; empty.hidden = true;
    var left = 68, right = 948, top = 16, bottom = 218;
    var min = Math.min.apply(Math, all), max = Math.max.apply(Math, all);
    var scale = max >= 1048576 ? 1048576 : max >= 1024 ? 1024 : 1;
    var axisUnit = scale === 1048576 ? "МиБ" : scale === 1024 ? "КиБ" : "Б";
    if (min === max) { var pad = Math.max(min * .08, 128); min = Math.max(0, min - pad); max += pad; }
    else { var margin = (max - min) * .08; min = Math.max(0, min - margin); max += margin; }
    for (var tick = 0; tick <= 4; tick++) {
      var y = top + (bottom - top) * tick / 4;
      chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: y, y2: y, "class": "diag-gridline" }));
      var label = svg(doc, "text", { x: left - 8, y: y + 4, "text-anchor": "end" });
      label.textContent = ((max - (max - min) * tick / 4) / scale).toFixed(scale === 1 ? 0 : 1);
      chart.appendChild(label);
    }
    chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: bottom, y2: bottom, "class": "diag-axis" }));
    var timedRows = rows.filter(function (row) { return number(row.time) !== null; });
    var firstTime = timedRows.length ? timedRows[0].time : null, lastTime = timedRows.length ? timedRows[timedRows.length - 1].time : null;
    var xLabelStart = svg(doc, "text", { x: left, y: 248, "text-anchor": "start" });
    var xLabelEnd = svg(doc, "text", { x: right, y: 248, "text-anchor": "end" });
    xLabelStart.textContent = timeLabel(rows[0].at);
    xLabelEnd.textContent = timeLabel(rows[rows.length - 1].at);
    chart.appendChild(xLabelStart); chart.appendChild(xLabelEnd);
    active.forEach(function (metric) {
      var commands = [], seen = 0, segment = false;
      rows.forEach(function (row, index) {
        var value = number(row[metric.key]);
        if (value === null) { segment = false; return; }
        var x = number(row.time) !== null && firstTime !== null && lastTime !== null && lastTime > firstTime ?
          left + (right - left) * (row.time - firstTime) / (lastTime - firstTime) :
          rows.length < 2 ? (left + right) / 2 : left + (right - left) * index / (rows.length - 1);
        if (metric.key === "rss" && seen > 0 && row.generation !== null && number(row.generation) !== null) {
          var previous = rows[index - 1];
          if (previous && previous.generation !== row.generation) segment = false;
        }
        var y = bottom - (bottom - top) * (value - min) / (max - min);
        commands.push((segment ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1));
        segment = true;
        seen++;
      });
      if (seen > 0) chart.appendChild(svg(doc, "path", { d: commands.join(" "), "class": "diag-line diag-line-" + metric.color, "data-series": metric.key }));
    });
    return { rows: rows, delta: seriesEndpoints(rows, "rss").delta, axisUnit: axisUnit };
  }
  function processRows(doc, samples, memoryRowsInRange, latestMemory) {
    var body = doc.getElementById("diagnostic-processes");
    if (!body) return { mismatch: null };
    body.replaceChildren();
    var labels = { d2kc: "Контроллер", d2kd: "Датапат", d2kpanel: "Панель" };
    var last = samples[samples.length - 1];
    if (!last || !list(last.processes).length) {
      var empty = doc.createElement("tr"), cell = doc.createElement("td"); cell.colSpan = 3; cell.textContent = "Данные процессов недоступны."; empty.appendChild(cell); body.appendChild(empty); return { mismatch: null };
    }
    var processMono = number(last.mono_ms), memoryAt = latestMemory && number(latestMemory.time);
    var compareMono = processMono !== null && latestMemory && latestMemory.time_domain === "mono";
    var processComparable = compareMono ? processMono / 1000 : number(last.at);
    var memoryComparable = compareMono ? memoryAt : latestMemory && number(latestMemory.at);
    var timeDifference = processComparable !== null && memoryComparable !== null ? Math.abs(processComparable - memoryComparable) : null;
    var aligned = timeDifference !== null && timeDifference <= 1;
    var mismatch = null;
    list(last.processes).forEach(function (proc) {
      var first = null, firstSample = null;
      samples.some(function (sample) {
        first = list(sample.processes).filter(function (item) { return item.name === proc.name && item.pid === proc.pid && number(item.rss_kib) !== null; })[0] || null;
        if (first) firstSample = sample;
        return !!first;
      });
      var known = kibBytes(number(proc.rss_kib)), delta = known !== null && firstSample && firstSample !== last && number(first.rss_kib) !== null ? known - first.rss_kib * 1024 : null;
      if (proc.name === "d2kc" && aligned && latestMemory && number(latestMemory.rss) !== null) {
        var historyRss = seriesEndpoints(memoryRowsInRange, "rss");
        if (known !== null && Math.abs(known - latestMemory.rss) > 1024) mismatch = { process: known, memory: latestMemory.rss };
        known = latestMemory.rss;
        delta = historyRss.delta;
      }
      var row = doc.createElement("tr"), name = doc.createElement("td"), code = doc.createElement("small");
      name.textContent = labels[proc.name] || proc.name; code.textContent = proc.name; name.appendChild(code); row.appendChild(name);
      [known === null ? "—" : formatBytes(known), delta === null ? "—" : formatDeltaBytes(delta)].forEach(function (value) {
        var item = doc.createElement("td"); item.textContent = value; row.appendChild(item);
      });
      body.appendChild(row);
    });
    var note = doc.getElementById("diagnostic-process-note");
    if (note) {
      var processAt = number(last.at), memoryWallAt = latestMemory && number(latestMemory.at);
      var timeNote = timeDifference === null ? "Время одного из последних снимков неизвестно." :
        aligned ? "Снимки процессов и памяти: " + timeLabel(processAt !== null ? processAt : memoryWallAt) + "." :
          "Снимок процессов: " + timeLabel(processAt) + "; памяти: " + timeLabel(memoryWallAt) + " (разница " + formatAge(timeDifference * 1000) + ").";
      note.textContent = timeNote + " Изменение d2kc — за выбранный период графика; остальных процессов — за доступную историю того же PID.";
    }
    return { mismatch: mismatch };
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
  function renderWarnings(doc, report, chart, hours, processMismatch, storageMismatch) {
    var box = doc.getElementById("diagnostic-warnings");
    if (!box) return;
    box.replaceChildren();
    var notices = [], delta = chart.delta, anomalies = list(report.anomalies);
    function add(kind, title, message, technical) {
      notices.push({ kind: kind, title: title, message: message, technical: technical || "" });
    }
    var lost = [
      ["events_overwritten", "записи завершений"], ["samples_overwritten", "минутные снимки"],
      ["memory_history_overwritten", "снимки памяти"], ["limit_transitions_overwritten", "переходы AIMD"],
      ["anomalies_overwritten", "аномалии"]
    ].map(function (entry) { return { key: entry[0], label: entry[1], count: number(report[entry[0]]) }; })
      .filter(function (entry) { return entry.count !== null && entry.count > 0; });
    if (lost.length) add("warning", "Часть истории вытеснена",
      "Кольцевые журналы перезаписали старые диагностические записи.",
      lost.map(function (entry) { return entry.label + " — " + entry.count; }).join("; "));
    if (processMismatch) add("warning", "Несогласованные снимки памяти",
      "В снимках с одной меткой времени RSS d2kc различается; значения оставлены у своих источников.",
      "Процессы: " + formatBytes(processMismatch.process) + "; история памяти: " + formatBytes(processMismatch.memory));
    if (storageMismatch && storageMismatch.length) add("warning", "Несовпадение объёмов в отчёте",
      "График и карточки показывают снимок истории памяти; общий отчёт содержит другие значения.", storageMismatch.join("; "));
    var growthAnomalies = anomalies.filter(function (item) { return item && item.kind === "unattributed-rss-growth"; });
    var growth = growthAnomalies[growthAnomalies.length - 1];
    if ((number(delta) !== null && delta > 0) || growth) {
      var growthText = number(delta) !== null && delta > 0 ? "RSS вырос на " + formatBytes(delta) + " за фактически доступную часть выбранных " + rangeText(hours) :
        "За " + pretty(number(growth.window_samples)) + " снимков RSS вырос на " + formatKib(growth.rss_delta_kib);
    if (growth) growthText += "; без сопоставимого роста учтённых объектов: за последние " +
      pretty(number(growth.window_samples)) + " снимков учтённая память изменилась на " +
        formatKib(number(growth.accounted_delta_kib));
      add("info", "Рост RSS", growthText + ". Рост сам по себе не подтверждает утечку.");
    }
    var rows = memoryRows(report), unavailableRows = rows.filter(function (row) { return row.status === 1 && row.anonymous === null; });
    var unavailable = unavailableRows.length;
    var unsupported = rows.filter(function (row) { return row.status === 4; }).length;
    var parseErrors = rows.filter(function (row) { return row.status === 3 && row.anonymous === null; }).length;
    var detail = detailsFor(report), latest = detail && detail.latest;
    var current = list(report.samples).slice(-1)[0];
    var currentPid = list(current && current.processes).filter(function (proc) { return proc.name === "d2kc"; })[0];
    var latestPid = number(latest && latest.pid);
    var liveOptionalMissing = latestPid !== null && currentPid && number(currentPid.pid) === latestPid && (
      (latest.smaps_rollup_errno === 2 && latest.smaps_rollup_status === "unavailable") ||
      (latest.smaps_errno === 2 && latest.smaps_status === "unavailable"));
    if (!unavailable && latest && latest.smaps_rollup_status === "unavailable" && latest.smaps_rollup_source !== "smaps-fallback" &&
        !rows.some(function (row) { return row.anonymous !== null; }) && !liveOptionalMissing) unavailable = 1;
    if (liveOptionalMissing && unavailableRows.every(function (row) { return row.errno === 2; })) {
      unsupported = Math.max(unsupported, unavailableRows.length || 1);
      unavailable = 0;
    }
    if (!unsupported && latest && latest.smaps_rollup_status === "unsupported") unsupported = 1;
    if (!parseErrors && latest && latest.smaps_rollup_status === "parse-error") parseErrors = 1;
    var fallback = latest && latest.smaps_rollup_source === "smaps-fallback";
    var unsupportedWithoutFallback = fallback ? 0 : unsupported;
    if (fallback && (unsupported || latest.smaps_rollup_status === "unsupported" || liveOptionalMissing)) {
      add("info", "Подробная карта памяти недоступна на этом устройстве",
        "Основные показатели доступны; Anonymous и Private_Dirty взяты из сохранённого отчёта.",
        "smaps_rollup отсутствует; использованы значения из smaps. RssAnon читается из /proc/PID/status.");
    }
    var unavailableError = rows.filter(function (row) { return row.status === 1 && row.errno !== null; })[0];
    unavailableError = unavailableError ? unavailableError.errno :
      (latest && latest.smaps_rollup_status === "unavailable" ? number(latest.smaps_rollup_errno) : null);
    if (unsupportedWithoutFallback) add("info", "Подробная карта памяти недоступна на этом устройстве",
      "RSS, RssAnon, VmData и учтённые D2O объекты продолжают собираться.",
      "В procfs отсутствует /proc/PID/smaps_rollup в " + unsupportedWithoutFallback + " " + sampleWord(unsupportedWithoutFallback) +
        ". Для Anonymous и Private_Dirty нужна прошивка с KERNEL_PROC_PAGE_MONITOR и CONFIG_PROC_PAGE_MONITOR=y.");
    if (unavailable) add("warning", "Не удалось прочитать подробную карту памяти",
      "Проверьте доступ к procfs и наличие процесса во время снимка.",
      unavailable + " " + sampleWord(unavailable) + (unavailableError !== null ? "; errno " + unavailableError : "; errno отсутствует"));
    if (parseErrors) add("warning", "Не удалось разобрать подробную карту памяти",
      "Повреждённый или неполный снимок исключён из графика.", parseErrors + " " + sampleWord(parseErrors));
    var writeErrors = anomalies.filter(function (item) { return item && item.kind === "diagnostic-json-write-error"; });
    var writeFailures = number(report.diagnostic_write_failures) || 0;
    if (writeFailures || writeErrors.length) {
      var writeError = writeErrors[writeErrors.length - 1];
      add("warning", "Не удалось сохранить диагностический JSON",
        "Часть отчёта могла не записаться; подробности остались в оперативном журнале.",
        "Сбоев: " + (writeFailures || writeErrors.length) + (writeError ? "; этап: " + (writeError.stage || "неизвестен") +
          (number(writeError.error_code) !== null ? "; errno " + writeError.error_code : "") : ""));
    }
    notices.forEach(function (notice) {
      var item = doc.createElement("section"), title = doc.createElement("strong"), text = doc.createElement("p");
      item.className = "diag-notice diag-notice--" + notice.kind;
      title.className = "diag-notice-title"; title.textContent = notice.title;
      text.className = "diag-notice-text"; text.textContent = notice.message;
      item.appendChild(title); item.appendChild(text);
      if (notice.technical) {
        var details = doc.createElement("details"), summary = doc.createElement("summary"), detail = doc.createElement("p");
        summary.textContent = "Технические подробности"; detail.textContent = notice.technical;
        details.appendChild(summary); details.appendChild(detail); item.appendChild(details);
      }
      box.appendChild(item);
    });
    box.hidden = notices.length === 0;
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
  function renderMemorySites(doc, report) {
    var listNode=doc.getElementById("diagnostic-memory-sites"),note=doc.getElementById("diagnostic-memory-tracking-coverage");
    if(!listNode||!note)return;listNode.replaceChildren();
    var tracking=report.memory_tracking;
    if(!tracking){note.textContent="Учёт подсистем отсутствует в старом формате отчёта.";return;}
    note.textContent=tracking.coverage||"Учёт начинается с выделений после включения сбора.";
    list(tracking.sites).forEach(function(site){
      var item=doc.createElement("li"),name=doc.createElement("strong"),location=doc.createElement("small");
      name.textContent=(site.name||site.id||"Объект")+": "+formatBytes(site.live_bytes)+" · "+pretty(number(site.live_objects))+" объектов · пик "+formatBytes(site.peak_bytes);
      location.textContent=(site.location||"")+" · выделено "+pretty(number(site.created))+", освобождено "+pretty(number(site.destroyed))+", ошибки выделения "+pretty(number(site.alloc_failures));
      item.appendChild(name);item.appendChild(location);listNode.appendChild(item);
    });
  }
  function renderMadvise(doc, report) {
    var m=report.madvise;
    setText(doc,"diagnostic-madvise-results",m?pretty(number(m.successes))+" / "+pretty(number(m.failures)):"—");
    setText(doc,"diagnostic-madvise-bytes",m?formatBytes(m.requested_bytes):"—");
    var errors=list(m&&m.errno).map(function(item){return number(item.code)+" × "+number(item.count);}).filter(function(item){return item.indexOf("null")<0;});
    if(m&&number(m.other_errno_count)>0)errors.push("прочие × "+m.other_errno_count);
    setText(doc,"diagnostic-madvise-errors",!m?"—":errors.join(" · ")||"нет");
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
    var allMemoryRows=memoryRows(report),intervalMs=number(mem&&mem.sample_interval_ms)||number(report.sample_interval_ms)||60000;
    if (!last && !memorySamples.length) {
      doc.getElementById("diagnostic-status").textContent = report.pending ? "Отчёт формируется. Ожидаем первый снимок." : "Ожидаем первый снимок. Отчёт обновляется по мере работы контроллера.";
    } else {
      var latestAt = last && number(last.at);
      if (latestAt === null && allMemoryRows.length) latestAt = allMemoryRows[allMemoryRows.length - 1].at;
      doc.getElementById("diagnostic-status").textContent = latestAt === null ? "История диагностики загружена." : "Обновлено " + new Date(latestAt * 1000).toLocaleTimeString() +
        (number(report.sample_interval_ms) !== null ? " · интервал " + formatAge(report.sample_interval_ms) : "");
    }
    setText(doc, "diagnostic-events", countWithCapacity(events.length, report.event_capacity));
    setText(doc, "diagnostic-unconfirmed", String(events.filter(function (event) { return ["failed", "inconclusive", "unknown", "local-abort", "queue-full"].indexOf(event.outcome) >= 0; }).length));
    setText(doc, "diagnostic-samples", countWithCapacity(samples.length, report.sample_capacity) + (memorySamples.length ? " · память: " + countWithCapacity(memorySamples.length, mem.capacity) : ""));
    setText(doc, "diagnostic-workers-running", pretty(number(last && last.workers_running)));
    setText(doc, "diagnostic-workers-result", pretty(number(last && last.workers_result_pending)));
    setText(doc, "diagnostic-workers-join", pretty(number(last && last.workers_join_pending)));
    setText(doc, "diagnostic-workers-oldest", last && number(last.worker_oldest_age_ms) !== null ? formatAge(last.worker_oldest_age_ms) + (last.worker_oldest_type ? " · " + last.worker_oldest_type : "") : "—");
    setText(doc, "diagnostic-workers-errors", last && (number(last.worker_start_failures) !== null || number(last.worker_join_failures) !== null) ?
      pretty(number(last.worker_start_failures)) + " / " + pretty(number(last.worker_join_failures)) : "—");
    var firstRow=allMemoryRows[0],lastRow=allMemoryRows[allMemoryRows.length-1];
    setText(doc,"diagnostic-workers-trend",firstRow&&lastRow&&firstRow.tasks!==null&&lastRow.tasks!==null&&firstRow.workers_live!==null&&lastRow.workers_live!==null?
      "задачи "+pretty(firstRow.tasks)+"→"+pretty(lastRow.tasks)+" · workers "+pretty(firstRow.workers_live)+"→"+pretty(lastRow.workers_live):"—");
    setText(doc, "diagnostic-catalog-bytes", formatBytes(firstDefined([lastRow && lastRow.catalog, last && last.catalog_bytes])));
    setText(doc, "diagnostic-snapshot-bytes", formatBytes(firstDefined([lastRow && lastRow.snapshot, last && last.snapshot_bytes])));
    setText(doc, "diagnostic-catalog-counts", last ? [last.boxes, last.bindings, last.plans].map(function (value) { return number(value) === null ? "—" : value; }).join(" / ") : "—");
    setText(doc, "diagnostic-http-bytes", formatBytes(firstDefined([lastRow && lastRow.http, last && last.http_bytes])));
    setText(doc, "diagnostic-http-records", last ? storageRow(last.http_records_bytes, firstDefined([last.http_records_limit_bytes, httpLimits.records_bytes])) : "—");
    setText(doc, "diagnostic-http-queue", last ? storageRow(last.http_queue_bytes, firstDefined([last.http_queue_limit_bytes, httpLimits.queue_bytes])) : "—");
    setText(doc, "diagnostic-http-evidence", last ? storageRow(last.http_failure_bytes, firstDefined([last.http_failure_limit_bytes, httpLimits.failures_bytes])) +
      (firstDefined([last.http_failure_record_limit_bytes, httpLimits.failure_record_bytes]) !== null ? " · до " + formatBytes(firstDefined([last.http_failure_record_limit_bytes, httpLimits.failure_record_bytes])) + " на сайт" : "") : "—");
    setText(doc, "diagnostic-http-overflows", last ? overflowText(last) : "—");
    var matchingSample=lastRow&&sampleForHistoryRow(report,lastRow.at,lastRow.time,lastRow.time_domain);
    var sharedSample=!!(matchingSample&&matchingSample===last);
    var sampleMono=number(last&&last.mono_ms),historyMono=lastRow&&lastRow.time_domain==="mono"?number(lastRow.time)*1000:null;
    var storageDifference=sampleMono!==null&&historyMono!==null?Math.abs(sampleMono-historyMono):null;
    var storageMismatch=[];
    if(sharedSample&&list(report.memory_history&&report.memory_history.fields).length) {
      [["catalog_bytes","catalog","Каталог"],["http_bytes","http","HTTP"],["snapshot_bytes","snapshot","Снимки"]].forEach(function(entry){
        if(list(report.memory_history.fields).indexOf(entry[0])<0||number(lastRow[entry[1]])===null||number(matchingSample[entry[0]])===null)return;
        if(lastRow[entry[1]]!==matchingSample[entry[0]])storageMismatch.push(entry[2]+": история "+formatBytes(lastRow[entry[1]])+", общий снимок "+formatBytes(matchingSample[entry[0]]));
      });
    }
    var storageNote=!lastRow ? "Объём, ограничения и счётчики — из последнего общего снимка." :
      storageMismatch.length ? "Время снимка совпадает, но объёмы расходятся; карточка следует истории графика." :
      sharedSample ? "Объём, ограничения и счётчики взяты из одного снимка." :
        "Объём — снимок истории памяти " + timeLabel(lastRow.at) + "; ограничения и счётчики — общий снимок " + timeLabel(last&&last.at) +
          (storageDifference!==null?" (разница " + formatAge(storageDifference) + ").":".");
    setText(doc,"diagnostic-catalog-note",storageNote);
    setText(doc,"diagnostic-http-note",storageNote);
    renderMemorySites(doc,report);renderMadvise(doc,report);
    renderAimd(doc, report, last);
    var chart = drawMemory(doc, allMemoryRows, range, intervalMs);
    setText(doc, "diagnostic-memory-interval", intervalText(intervalMs, chart.axisUnit));
    setText(doc, "diagnostic-history-coverage", coverageText(chart.rows, range));
    var latestMemory=allMemoryRows.length?allMemoryRows[allMemoryRows.length-1]:null;
    var processState=processRows(doc,samples,chart.rows,latestMemory);
    renderWarnings(doc, report, chart, range, processState.mismatch, storageMismatch);
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
    var memoryRowsLatest=memoryRows(report),lastMemory=memoryRowsLatest[memoryRowsLatest.length-1];
    var rssAnon=lastMemory&&lastMemory.rss_anon!==null?lastMemory.rss_anon/1024:
      number(list(last&&last.processes).filter(function(p){return p.name==="d2kc";})[0]&&list(last&&last.processes).filter(function(p){return p.name==="d2kc";})[0].anon_kib);
    var catalogBytes=firstDefined([last&&last.catalog_bytes,lastMemory&&lastMemory.catalog]);
    var tracker=report.memory_tracking||{},sites=list(tracker.sites),madvise=report.madvise||{},anomalies=list(report.anomalies);
    var extras=(rssAnon===null?"":" RssAnon: "+formatKib(rssAnon)+".")+
      (catalogBytes!==null?" Память каталога: "+formatBytes(catalogBytes)+".":"")+
      (sites.length?" Инструментированные подсистемы: "+sites.map(function(site){return (site.name||site.id)+" "+formatBytes(site.live_bytes);}).join(", ")+".":"")+
      (report.madvise?" madvise успешно / ошибка: "+pretty(number(madvise.successes))+" / "+pretty(number(madvise.failures))+".":"")+
      (anomalies.some(function(item){return item.kind==="unattributed-rss-growth";})?" Зафиксирован устойчивый рост RSS без сопоставимого роста учтённых объектов; это не подтверждает утечку.":"");
    var unsupported=detailsFor(report),latestDetail=unsupported&&unsupported.latest;
    if(latestDetail&&latestDetail.smaps_rollup_status==="unsupported")extras+=" В procfs отсутствует smaps_rollup; RssAnon читается из status.";
    if(latestDetail&&latestDetail.smaps_rollup_source==="smaps-fallback")extras+=" Anonymous и Private_Dirty получены из smaps.";
    return "Снимков: " + countWithCapacity(samples.length, report.sample_capacity) + "; завершений поиска: " + countWithCapacity(events.length, report.event_capacity) +
      ", без подтверждённого результата: " + failures + ". " + (rss ? "RSS d2kc: " + formatKib(rss.rss_kib) +
      (first ? " (" + ((rss.rss_kib - first.rss_kib) >= 0 ? "+" : "") + ((rss.rss_kib - first.rss_kib) / 1024).toFixed(1) + " за историю этого PID)" : "") + ". " : "") +
      "Снимков памяти: " + countWithCapacity(list(memory.samples).length, memory.capacity) +
      extras;
  }
  if (typeof module === "object" && module.exports) module.exports = {
    summary: summary, memoryRows: memoryRows, rowsInRange: rowsInRange,
    seriesEndpoints: seriesEndpoints, formatBytes: formatBytes, coverageText: coverageText
  };
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
