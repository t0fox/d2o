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
      chart.setAttribute("hidden", "");
      empty.hidden = false;
      empty.textContent = !active.length && rows.length ? "Выберите доступный показатель памяти." : "Для выбранного периода нет доступных снимков памяти.";
      return { rows: rows, delta: null, axisUnit: null };
    }
    chart.removeAttribute("hidden"); empty.hidden = true;
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
  function telegramRows(tg) {
    var memory=tg&&tg.memory_history||{}, fields=list(memory.fields), rows=list(memory.samples), base=list(memory.time_base);
    var wall=number(base[0]),mono=number(base[1]);
    function field(row,key) { var index=fields.indexOf(key);return index<0?null:number(row[index]); }
    return rows.map(function(row) {
      if(!Array.isArray(row))return null;
      var atDelta=field(row,"at_delta_s"),monoDelta=field(row,"mono_delta_s");
      var at=wall===null||atDelta===null?null:wall+atDelta;
      var time=mono!==null&&monoDelta!==null?mono+monoDelta:at;
      return {at:at,time:time,process_id:field(row,"process_id"),process_started_at:field(row,"process_started_at"),
        process_generation:field(row,"process_generation"),
        rss:kibBytes(field(row,"rss_kib")),rss_hwm:kibBytes(field(row,"rss_hwm_kib")),
        rss_anon:kibBytes(field(row,"rss_anon_kib")),vm_data:kibBytes(field(row,"vm_data_kib")),
        vm_swap:kibBytes(field(row,"vm_swap_kib")),smaps_pss:kibBytes(field(row,"smaps_pss_kib")),
        smaps_private_dirty:kibBytes(field(row,"smaps_private_dirty_kib")),
        mem_available:kibBytes(field(row,"mem_available_kib")),mem_total:kibBytes(field(row,"mem_total_kib")),
        known_bytes:field(row,"memory_accounted_allocations_bytes"),buffer_current:field(row,"buffer_bytes_current"),
        proxy_bytes:field(row,"proxy_struct_bytes"),connection_bytes:field(row,"connection_struct_bytes"),
        retired_connection_bytes:field(row,"retired_connection_struct_bytes"),
        worker_pool_bytes:field(row,"worker_pool_struct_bytes"),
        active_connections:field(row,"active_connections"),fd_count:field(row,"fd_count"),
        tls_objects:field(row,"tls_objects"),worker_pool_tls_objects:field(row,"worker_pool_tls_objects"),
        worker_pool_entries:field(row,"worker_pool_entries"),
        buffer_bytes_limit:field(row,"buffer_bytes_limit"),memory_ceiling_bytes:field(row,"memory_ceiling_bytes"),
        max_connections:field(row,"max_connections"),soft_nofile_limit:field(row,"soft_nofile_limit"),
        bytes_from_clients:field(row,"bytes_from_clients"),bytes_from_upstreams:field(row,"bytes_from_upstreams"),
        http_403:field(row,"http_403"),http_501:field(row,"http_501"),http_502:field(row,"http_502"),
        wss_attempts:field(row,"wss_attempts"),wss_failures:field(row,"wss_failures"),wss_responses:field(row,"wss_responses"),
        cf_wss_responses:field(row,"cf_wss_responses"),buffer_budget_rejections:field(row,"buffer_budget_rejections"),
        accept_fd_exhaustion:field(row,"accept_fd_exhaustion"),
        client_response_latency_p50_us:field(row,"client_response_latency_p50_us"),
        client_response_latency_p95_us:field(row,"client_response_latency_p95_us")};
    }).filter(Boolean).map(function(row,index,rows){
      var previous=index?rows[index-1]:null,elapsed=previous&&number(row.time)!==null&&number(previous.time)!==null
        ?row.time-previous.time:0;
      if(previous&&elapsed>0&&sameTelegramProcess(row,previous)){
        var clients=number(row.bytes_from_clients),previousClients=number(previous.bytes_from_clients);
        var upstreams=number(row.bytes_from_upstreams),previousUpstreams=number(previous.bytes_from_upstreams);
        row.client_rate=clients!==null&&previousClients!==null&&clients>=previousClients?(clients-previousClients)/elapsed:null;
        row.upstream_rate=upstreams!==null&&previousUpstreams!==null&&upstreams>=previousUpstreams?(upstreams-previousUpstreams)/elapsed:null;
      }else row.client_rate=row.upstream_rate=null;
      return row;
    });
  }
  function sameTelegramProcess(a,b) {
    if(number(a.process_id)===null||a.process_id!==b.process_id)return false;
    var generationA=number(a.process_generation),generationB=number(b.process_generation);
    if(generationA!==null||generationB!==null)return generationA!==null&&generationA===generationB;
    return number(a.process_started_at)!==null&&a.process_started_at===b.process_started_at;
  }
  function telegramCounterDelta(rows,key) {
    var total=0,found=false;
    for(var i=1;i<rows.length;i++){
      var previous=rows[i-1],current=rows[i],before=number(previous[key]),after=number(current[key]);
      if(!sameTelegramProcess(previous,current)||before===null||after===null||after<before)continue;
      total+=after-before;found=true;
    }
    return found?total:null;
  }
  function telegramLimitChanges(tg) {
    var fields=[{key:"buffer_bytes_limit",label:"Буферы",bytes:true},
      {key:"memory_ceiling_bytes",label:"Потолок памяти",bytes:true},
      {key:"max_connections",label:"Максимум соединений"},
      {key:"soft_nofile_limit",label:"Предел FD"}],previous={},changes=[];
    telegramRows(tg).forEach(function(row){fields.forEach(function(item){
      var value=number(row[item.key]);if(value===null)return;
      if(Object.prototype.hasOwnProperty.call(previous,item.key)&&previous[item.key]!==value)
        changes.push({at:row.at,label:item.label,from:previous[item.key],to:value,bytes:item.bytes});
      previous[item.key]=value;
    });});
    return changes;
  }
  function telegramSessionRate(session,key) {
    var bytes=number(session[key]),age=number(session.age_ms);
    return bytes===null||age===null||age<=0?null:bytes*1000/age;
  }
  function drawTelegramChart(doc,tg,hours,chartId,emptyId,series,title,suffix,seriesAttribute,breakOnNull) {
    var chart=doc.getElementById(chartId),empty=doc.getElementById(emptyId);
    if(!chart||!empty)return;
    var memory=tg&&tg.memory_history||{},all=telegramRows(tg),rows=rowsInRange(all,hours,number(memory.sample_interval_ms)||60000);
    var active=series.filter(function(item){
      var input=doc.querySelector('['+seriesAttribute+'="'+item.key+'"]');
      var available=rows.some(function(row){return number(row[item.key])!==null;});
      if(input){input.parentNode.hidden=!available;item.checked=input.checked;}
      else if(item.checked===undefined)item.checked=true;
      return available&&item.checked;
    });
    chart.replaceChildren();chart.dataset.points=String(rows.length);
    chart.setAttribute("aria-label",title+" Telegram прокси за "+hours+" часа, точек: "+rows.length);
    var values=[];active.forEach(function(item){rows.forEach(function(row){if(number(row[item.key])!==null)values.push(row[item.key]);});});
    if(!rows.length||!values.length){chart.setAttribute("hidden","");empty.hidden=false;return;}
    chart.removeAttribute("hidden");empty.hidden=true;
    var left=68,right=948,top=16,bottom=218,min=Math.min.apply(Math,values),max=Math.max.apply(Math,values);
    var scale=max>=1048576?1048576:max>=1024?1024:1,unit=(scale===1048576?"МиБ":scale===1024?"КиБ":"Б")+suffix;
    if(min===max){var pad=Math.max(min*.08,128);min=Math.max(0,min-pad);max+=pad;}else{var margin=(max-min)*.08;min=Math.max(0,min-margin);max+=margin;}
    for(var tick=0;tick<=4;tick++){
      var y=top+(bottom-top)*tick/4;chart.appendChild(svg(doc,"line",{x1:left,x2:right,y1:y,y2:y,"class":"diag-gridline"}));
      var label=svg(doc,"text",{x:left-8,y:y+4,"text-anchor":"end"});label.textContent=((max-(max-min)*tick/4)/scale).toFixed(scale===1?0:1);chart.appendChild(label);
    }
    chart.appendChild(svg(doc,"line",{x1:left,x2:right,y1:bottom,y2:bottom,"class":"diag-axis"}));
    var first=rows[0].time,last=rows[rows.length-1].time;
    var start=svg(doc,"text",{x:left,y:248,"text-anchor":"start"}),end=svg(doc,"text",{x:right,y:248,"text-anchor":"end"});
    start.textContent=timeLabel(rows[0].at);end.textContent=timeLabel(rows[rows.length-1].at);chart.appendChild(start);chart.appendChild(end);
    active.forEach(function(item){
      var points=[],previous=null;
      function flush(){
        var style="diag-line diag-line-"+item.color;
        if(points.length===1){
          var xy=points[0].slice(1).split(",");
          chart.appendChild(svg(doc,"circle",{"class":style,cx:xy[0],cy:xy[1],r:2}));
        }else if(points.length){
          chart.appendChild(svg(doc,"path",{"class":style,d:points.join(" ")}));
        }
        points=[];
      }
      rows.forEach(function(row,index){var value=number(row[item.key]);
        if(previous&&!sameTelegramProcess(previous,row))flush();
        if(value===null){if(breakOnNull)flush();previous=row;return;}
        var x=number(row.time)!==null&&first!==null&&last!==null&&last>first?left+(right-left)*(row.time-first)/(last-first):left+(right-left)*index/Math.max(1,rows.length-1);
        var y=bottom-(bottom-top)*(value-min)/(max-min);points.push((points.length?"L":"M")+x.toFixed(1)+","+y.toFixed(1));previous=row;
      });
      flush();
    });
    return {rows:rows,unit:unit};
  }
  function drawTelegramMemory(doc,tg,hours) {
    var result=drawTelegramChart(doc,tg,hours,"telegram-diagnostic-memory-chart","telegram-diagnostic-memory-empty",
      [{key:"rss",color:"rss"},{key:"rss_anon",color:"rss_anon"},
       {key:"rss_hwm",color:"tracked_tcp"},{key:"vm_data",color:"vm_data"},
       {key:"vm_swap",color:"tracked_tls"},{key:"smaps_pss",color:"anonymous"},
       {key:"smaps_private_dirty",color:"private_dirty"},{key:"mem_available",color:"http"},
       {key:"known_bytes",color:"tracked_tcp"},
       {key:"buffer_current",color:"snapshot"},{key:"proxy_bytes",color:"http"},
       {key:"connection_bytes",color:"anonymous"},{key:"retired_connection_bytes",color:"private_dirty"},
       {key:"worker_pool_bytes",color:"tracked_quic"}],"Память","","data-tg-memory-series",true);
    var memory=tg&&tg.memory_history||{};
    if(result){setText(doc,"telegram-diagnostic-memory-interval","Снимок раз в "+Math.floor((number(memory.sample_interval_ms)||60000)/60000)+" мин · ось в "+result.unit);
      setText(doc,"telegram-diagnostic-history-coverage",coverageText(result.rows,hours));}
  }
  function drawTelegramTraffic(doc,tg,hours) {
    return drawTelegramChart(doc,tg,hours,"telegram-diagnostic-traffic-chart","telegram-diagnostic-traffic-empty",
      [{key:"client_rate",color:"rss"},{key:"upstream_rate",color:"rss_anon"}],
      "Скорость передачи","/с","data-tg-traffic-series",true);
  }
  function drawTelegramResources(doc,tg,hours) {
    return drawTelegramChart(doc,tg,hours,"telegram-diagnostic-resource-chart","telegram-diagnostic-resource-empty",
      [{key:"active_connections",color:"rss"},{key:"fd_count",color:"rss_anon"},
       {key:"tls_objects",color:"tracked_tls"},{key:"worker_pool_tls_objects",color:"private_dirty"},
       {key:"worker_pool_entries",color:"http"}],
      "Ресурсы","","data-tg-resource-series",true);
  }
  function telegramLatestValue(latest,key) { return number(latest&&latest[key]); }
  function telegramUnavailable(value) { return value===null||value===undefined||value==="unavailable"?"—":null; }
  function telegramBytes(value) { return telegramUnavailable(number(value))||formatBytes(value); }
  function telegramKib(value) { return telegramUnavailable(number(value))||formatKib(value); }
  function telegramCountText(value) { return telegramUnavailable(number(value))||pretty(value); }
  function telegramAgeText(value) { return telegramUnavailable(number(value))||formatAge(value); }
  function telegramPretty(value) { return telegramUnavailable(value)||pretty(value); }
  function telegramTime(value) { return telegramUnavailable(number(value))||timeLabel(value); }
  function telegramMetricRows(doc, list, entries) {
    list.replaceChildren();
    entries.forEach(function(entry) {
      if (entry[1] === null) return;
      var row = doc.createElement("div"), label = doc.createElement("dt"), value = doc.createElement("dd");
      label.textContent = entry[0];
      value.textContent = entry[1];
      row.append(label, value);
      list.appendChild(row);
    });
  }
  function telegramStatusLabel(value) {
    var labels = {fresh:"Актуальна",expired:"Срок истёк",clock_skew:"Расхождение часов",
      loaded:"Загружена",loaded_last_good:"Загружена рабочая копия",never:"Ещё не запускалось",
      success:"Успешно",running:"В процессе",no_snapshot:"Снимка пока нет",
      http_error:"Ошибка HTTP",discovery_failed:"Не удалось получить карту",
      install_failed:"Не удалось сохранить карту",thread_start_failed:"Не удалось начать обновление"};
    return labels[value] || telegramPretty(value);
  }
  function renderTelegramMetrics(doc, data, latest, history) {
    var formats = {k:telegramKib,b:telegramBytes,n:telegramCountText,age:telegramAgeText,time:telegramTime,
      status:telegramStatusLabel,yes:function(v){return v?"Да":"Нет";},
      us:function(v){return (v/1000).toFixed(1)+" мс";},delta:formatDeltaBytes};
    Array.from(data.querySelectorAll("[data-tg-field]")).forEach(function(element){
      var key=element.dataset.tgField, value=latest[key], limit=latest[element.dataset.limit];
      var available=value!==null&&value!==undefined&&value!=="unavailable";
      var fmt=formats[element.dataset.format];
      if(element.dataset.format==="us" && latest.client_response_latency_samples===0)available=false;
      element.parentNode.hidden=!available;
      element.textContent=available?fmt(value)+(limit===null||limit===undefined?"":" / "+fmt(limit)):"";
    });
    var smaps=latest.smaps_rollup_status;
    setText(doc,"tg-diag-smaps-status",smaps==="ok"?"":smaps==="unsupported"?
      "PSS и разбивка страниц недоступны: ядро не предоставляет smaps_rollup.":
      (smaps==="parse_error"||smaps==="parse-error")?"Не удалось разобрать smaps_rollup.":
      "Снимок smaps_rollup недоступен."+(number(latest.smaps_rollup_errno)===null?"":" Код "+latest.smaps_rollup_errno+"."));
    var rate=history[history.length-1];
    telegramMetricRows(doc,doc.getElementById("tg-diag-rate-details"),[
      ["От клиента за минутный интервал", rate&&rate.client_rate!==null?telegramBytes(rate.client_rate)+"/с":null],
      ["От сервера за минутный интервал", rate&&rate.upstream_rate!==null?telegramBytes(rate.upstream_rate)+"/с":null]
    ]);
    var errorKeys=["http_403","http_501","http_502","wss_failures"];
    telegramMetricRows(doc,doc.getElementById("tg-diag-period-errors"),errorKeys.map(function(key,i){
      var value=telegramCounterDelta(history,key);
      return [["Новые HTTP 403","Новые HTTP 501","Новые HTTP 502","Новые ошибки WSS"][i],value===null?null:telegramCountText(value)];
    }));
    var stages=latest.failure_by_stage||{};
    telegramMetricRows(doc,doc.getElementById("tg-diag-stage-failures"),Object.keys(stages)
      .filter(function(key){return stages[key]>0;}).map(function(key){return [key,telegramCountText(stages[key])];}));
  }
  function renderTelegram(doc,tg,enabled,range) {
    var state=doc.getElementById("telegram-diagnostic-state"),data=doc.getElementById("telegram-diagnostic-data");
    if(!state||!data)return;
    state.textContent=enabled?"Сбор включён":"Сбор выключен";state.dataset.enabled=String(enabled);data.hidden=!enabled;
    if(!enabled){setText(doc,"telegram-diagnostic-status","Сбор выключен. Включите его, чтобы записывать память и состояние Telegram прокси.");return;}
    tg=tg||{};var latest=tg.latest||null,history=telegramRows(tg),last=history[history.length-1];
    var failed=tg.collection_status==="socket_unavailable";
    var error=number(tg.last_error)===null?"":" (код "+tg.last_error+")";
    data.hidden=!latest;
    if(!latest){
      setText(doc,"telegram-diagnostic-status",failed?
        "Не удалось получить статистику Telegram-прокси"+error+". Повторяем подключение автоматически.":
        "Ожидаем первый снимок Telegram-прокси.");
      return;
    }
    setText(doc,"telegram-diagnostic-status",(failed?
      "Текущий срез недоступен"+error+". Ниже последний успешный снимок. ":
      "Снимков памяти: "+countWithCapacity(history.length,(tg.memory_history||{}).capacity)+" · ")+
      "последнее чтение: "+(number(tg.last_sample_at)===null?"—":new Date(tg.last_sample_at*1000).toLocaleTimeString())+
      (tg.collection_failures?" · ошибок чтения: "+tg.collection_failures:""));
    drawTelegramMemory(doc,tg,range);drawTelegramTraffic(doc,tg,range);drawTelegramResources(doc,tg,range);
    renderTelegramMetrics(doc,data,latest,history);
    function renderRecords(id, emptyId, records, fields) {
      var container=doc.getElementById(id);
      var open = new Set(Array.from(container.querySelectorAll("details[open]")).map(function(node){return node.dataset.record;}));
      container.replaceChildren();
      records.forEach(function(record) {
        var details=doc.createElement("details"), summary=doc.createElement("summary"), body=doc.createElement("dl");
        var entries=fields(record);
        summary.textContent=entries.shift()[1];
        details.dataset.record=record.id===undefined?summary.textContent:record.id;
        details.open=open.has(details.dataset.record);
        details.className="tg-diag-record";
        body.className="tg-diag-metrics";
        telegramMetricRows(doc,body,entries);
        details.append(summary,body);
        container.appendChild(details);
      });
      doc.getElementById(emptyId).hidden=records.length>0;
    }
    var routeHealth=Array.isArray(latest.route_health);
    var dcCard=doc.getElementById("tg-diag-dc-card");
    if(dcCard)dcCard.hidden=Array.from(dcCard.querySelectorAll("[data-tg-field]"))
      .every(function(element){return element.parentNode.hidden;});
    setText(doc,"tg-diag-routes-empty",routeHealth?"Пока нет данных маршрута.":
      "Маршрутов на паузе в снимке нет.");
    setText(doc,"tg-diag-route-title",routeHealth?"Маршруты":"Маршруты на паузе");
    renderRecords("tg-diag-routes","tg-diag-routes-empty",routeHealth?latest.route_health:list(latest.route_cooldowns),function(route){
      var ports=number(route.client_port)>0&&number(route.upstream_port)>0?route.client_port+" → "+route.upstream_port:null;
      var pause=routeHealth?route.cooldown_remaining_ms:route.remaining_ms;
      return [["", "DC "+telegramPretty(route.dc)+" · "+(route.is_media?"Медиа":"Основной")+" · "+telegramPretty(route.transport)],
        ["Порты",ports],["Попытки",number(route.attempts)===null?null:telegramCountText(route.attempts)],
        ["Ответы",number(route.responses)===null?null:telegramCountText(route.responses)],
        ["Ошибки",number(route.failures)===null?null:telegramCountText(route.failures)],
        ["Пауза",number(pause)>0?telegramAgeText(pause):null]];
    });
    renderRecords("tg-diag-sessions","tg-diag-sessions-empty",list(latest.active_sessions),function(session){
      var kind=session.is_media===true?"Медиа":session.is_media===false?"Основная":"Тип неизвестен";
      var fromClient=telegramSessionRate(session,"bytes_from_clients"), fromUpstream=telegramSessionRate(session,"bytes_from_upstreams");
      return [["","#"+telegramPretty(session.id)+" · DC "+telegramPretty(session.dc)+" · "+kind],
        ["Маршрут",session.selected_transport||session.direct_transport||session.fallback_transport||null],
        ["Возраст",number(session.age_ms)===null?null:telegramAgeText(session.age_ms)],
        ["От клиента",telegramBytes(session.bytes_from_clients)+(fromClient===null?"":" · "+telegramBytes(fromClient)+"/с")],
        ["От сервера",telegramBytes(session.bytes_from_upstreams)+(fromUpstream===null?"":" · "+telegramBytes(fromUpstream)+"/с")],
        ["Первый ответ",number(session.first_response_latency_ms)===null?null:telegramAgeText(session.first_response_latency_ms)],
        ["Без прогресса",number(session.no_progress_ms)===null?null:telegramAgeText(session.no_progress_ms)],
        ["Очередь к клиенту",number(session.client_queue_bytes)===null?null:telegramBytes(session.client_queue_bytes)+" / "+telegramBytes(session.client_queue_capacity_bytes)],
        ["Очередь к серверу",number(session.upstream_queue_bytes)===null?null:telegramBytes(session.upstream_queue_bytes)+" / "+telegramBytes(session.upstream_queue_capacity_bytes)],
        ["Основной маршрут",session.direct_state+(session.direct_transport?" · "+session.direct_transport:"")],
        ["Запасной маршрут",session.fallback_state+(session.fallback_transport?" · "+session.fallback_transport:"")],
        ["Состояние",session.read_paused?"Чтение приостановлено":session.stage]];
    });
    var problems=doc.getElementById("tg-diag-problems");problems.replaceChildren();
    list(latest&&latest.problem_sessions).slice().reverse().slice(0,8).forEach(function(problem){var li=doc.createElement("li");
      li.textContent="DC "+telegramPretty(problem.dc)+" · "+telegramPretty(problem.failure_stage)+
        (problem.http_status?" HTTP "+problem.http_status:"")+" · "+telegramPretty(problem.transport)+
        " · клиент/сервер "+telegramBytes(problem.bytes_from_clients)+" / "+telegramBytes(problem.bytes_from_upstreams);problems.appendChild(li);
    });
    if(!Array.isArray(latest.problem_sessions)&&number(latest.last_failure_stage)>0){
      var failure=doc.createElement("li"), flow=root.D2kTelegramFlow;
      var lastFailure=flow&&flow.summarizeTelegramFlow(latest).latestFailure;
      if(lastFailure){failure.textContent="Последняя ошибка: "+lastFailure.stage+" · "+lastFailure.dc+
        " · "+lastFailure.route+" · "+telegramAgeText(lastFailure.ageMs)+" назад";problems.appendChild(failure);}
    }
    if(!problems.children.length){var empty=doc.createElement("li");empty.className="diag-transition-empty";
      empty.textContent=Array.isArray(latest.problem_sessions)?"Зафиксированных ошибок нет.":"Последняя ошибка не указана в снимке.";problems.appendChild(empty);}
    var limitHistory=doc.getElementById("tg-diag-limit-history"),changes=telegramLimitChanges(tg).slice(-20).reverse();
    limitHistory.replaceChildren();
    if(!changes.length){var emptyLimit=doc.createElement("li"),limitValues=["buffer_bytes_limit","memory_ceiling_bytes","max_connections","soft_nofile_limit"];
      emptyLimit.className="diag-transition-empty";
      emptyLimit.textContent=history.some(function(row){return limitValues.some(function(key){return number(row[key])!==null;});})
        ?"Изменений за сохранённые снимки нет.":"Лимиты в снимке отсутствуют.";limitHistory.appendChild(emptyLimit);}
    changes.forEach(function(change){var row=doc.createElement("li"),strong=doc.createElement("strong"),label=doc.createElement("span"),time=doc.createElement("small");
      var format=change.bytes?formatBytes:pretty;strong.textContent=change.label+": "+format(change.from)+" → "+format(change.to);
      label.textContent="Изменение между снимками";time.textContent=number(change.at)===null?"":new Date(change.at*1000).toLocaleString();
      row.appendChild(strong);row.appendChild(label);row.appendChild(time);limitHistory.appendChild(row);
    });
  }
  if (typeof module === "object" && module.exports) module.exports = {
    summary: summary, memoryRows: memoryRows, rowsInRange: rowsInRange,
    seriesEndpoints: seriesEndpoints, formatBytes: formatBytes, coverageText: coverageText,
    telegramRows: telegramRows
  };
  if (!root.document || !root.fetch) return;
  function boot() {
    var doc = root.document, toggle = doc.getElementById("diagnostic-toggle"), tgToggle = doc.getElementById("telegram-diagnostic-toggle"), status = doc.getElementById("diagnostic-status"), download = doc.getElementById("diagnostic-download");
    if (!toggle || !tgToggle || !status || !download) return;
    var enabled = false, telegramEnabled = false, busy = false, range = 2, telegramRange = 2, currentReport = {};
    function redraw() { render(currentReport, enabled, range);renderTelegram(doc,currentReport.telegram_diagnostics,telegramEnabled,telegramRange); }
    var tabs=Array.prototype.slice.call(doc.querySelectorAll("[data-diagnostic-tab]"));
    var selectedTab;
    function selectTab(name,focus) {
      selectedTab=name;
      tabs.forEach(function(tab){var selected=tab.dataset.diagnosticTab===name;tab.setAttribute("aria-selected",String(selected));tab.tabIndex=selected?0:-1;
        var panel=doc.querySelector('[data-diagnostic-panel="'+tab.dataset.diagnosticTab+'"]');if(panel)panel.hidden=!selected;if(selected&&focus)tab.focus();});
    }
    tabs.forEach(function(tab,index){
      tab.addEventListener("click",function(){selectTab(tab.dataset.diagnosticTab,false);});
      tab.addEventListener("keydown",function(event){var target=index;
        if(event.key==="ArrowRight")target=(index+1)%tabs.length;else if(event.key==="ArrowLeft")target=(index+tabs.length-1)%tabs.length;
        else if(event.key==="Home")target=0;else if(event.key==="End")target=tabs.length-1;else return;
        event.preventDefault();selectTab(tabs[target].dataset.diagnosticTab,true);
      });
    });
    doc.querySelectorAll("[data-memory-range]").forEach(function (button) {
      button.addEventListener("click", function () {
        range = Number(button.dataset.memoryRange);
        doc.querySelectorAll("[data-memory-range]").forEach(function (item) { item.setAttribute("aria-pressed", String(item === button)); });
        redraw();
      });
    });
    doc.querySelectorAll("[data-memory-series]").forEach(function (input) { input.addEventListener("change", redraw); });
    doc.querySelectorAll("[data-tg-memory-range]").forEach(function(button){button.addEventListener("click",function(){
      telegramRange=Number(button.dataset.tgMemoryRange);
      doc.querySelectorAll("[data-tg-memory-range]").forEach(function(item){item.setAttribute("aria-pressed",String(item===button));});redraw();
    });});
    doc.querySelectorAll("[data-tg-memory-series]").forEach(function(input){input.addEventListener("change",redraw);});
    doc.querySelectorAll("[data-tg-resource-series]").forEach(function(input){input.addEventListener("change",redraw);});
    function refresh() {
      return root.fetch("/api/diagnostics?status",{cache:"no-store"}).then(function(statusResponse){
        if(!statusResponse.ok)throw new Error("Ошибка HTTP "+statusResponse.status);return statusResponse.json();
      }).then(function(flags){return root.fetch("/api/diagnostics?report",{cache:"no-store"}).then(function(reportResponse){
        if(!reportResponse.ok&&reportResponse.status!==503)throw new Error("Ошибка HTTP "+reportResponse.status);
        return reportResponse.json().then(function(report){report=report||{};report.general_enabled=flags.enabled===true;
          report.telegram_enabled=flags.telegram_enabled===true;return report;});
      });}).then(function (r) {
        currentReport = r || {};
        enabled = typeof currentReport.general_enabled==="boolean"?currentReport.general_enabled:
          currentReport.enabled===true&&currentReport.telegram_enabled!==true;
        telegramEnabled = currentReport.telegram_enabled===true;
        toggle.textContent = enabled ? "Выключить и удалить историю" : "Включить сбор";
        tgToggle.textContent = telegramEnabled ? "Выключить и удалить историю Telegram" : "Включить сбор Telegram";
        download.hidden = !(enabled||telegramEnabled) || !!currentReport.pending;
        redraw();
      }).catch(function () { status.textContent = "Не удалось прочитать состояние диагностики."; });
    }
    function switchCollector(isTelegram) {
      if (busy) return;busy=true;toggle.disabled=true;tgToggle.disabled=true;
      var on=isTelegram?telegramEnabled:enabled;
      var action=isTelegram?(on?"telegram-disable":"telegram-enable"):(on?"disable":"enable");
      root.fetch("/api/diagnostics?"+action,{method:"POST",cache:"no-store"}).then(function (r) {
        if (!r.ok) throw new Error("Ошибка HTTP " + r.status);
        return refresh();
      }).catch(function () { setText(doc,isTelegram?"telegram-diagnostic-status":"diagnostic-status","Не удалось переключить сбор. Требуется доступ к управлению этой панелью."); })
        .finally(function () { busy=false;toggle.disabled=false;tgToggle.disabled=false; });
    }
    toggle.addEventListener("click",function(){switchCollector(false);});
    tgToggle.addEventListener("click",function(){switchCollector(true);});
    selectTab("general",false);
    refresh();
    var lastRefresh=Date.now();
    root.setInterval(function () {
      var waiting=selectedTab==="telegram"&&telegramEnabled&&
        !(currentReport.telegram_diagnostics||{}).latest;
      if(!busy&&!doc.hidden&&(waiting||Date.now()-lastRefresh>=60000)){
        lastRefresh=Date.now();
        refresh();
      }
    },5000);
  }
  if (root.document.readyState === "loading") root.document.addEventListener("DOMContentLoaded", boot); else boot();
})(typeof window !== "undefined" ? window : this);
