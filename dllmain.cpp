// dllmain.cpp - Dynamic language table injection hook
#include "pch.h"
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include "MinHook.h"

#pragma comment(lib, "psapi.lib")

// -------------------- Configuration --------------------
// Set this to the offset of FUN_145cc6360 in your target executable
#define FUNCTION_OFFSET 0x5cc6360

// -------------------- Language Entry Structure --------------------
struct LanguageEntry {
    uint64_t key;
    uint64_t value;
    const char* name;  // For logging purposes
};


// -------------------- CONFIGURE YOUR LANGUAGES HERE --------------------
static std::vector<LanguageEntry> g_LanguagesToAdd = {
                                            // in LangId (In .Lng2 files)
    { 6,  0x00FB22736BF48BULL, "Arabic" },  // 0x00FB22736BF48BULL == option_lan_ar
    //{ 9,  0x00BBC1DCE60188ULL, "Chinese" }, // 0x00BBC1DCE60188ULL == option_lan_ch
	//{ 10, 0x003ED6888202BFULL, "Korean" },  // 0x003ED6888202BFULL == option_lan_ko
};

// -------------------- Globals --------------------
static FILE* g_LogFile = nullptr;
static void* g_TargetAddress = nullptr;
typedef void(__fastcall* fnOriginal_t)(void*);
static fnOriginal_t g_fpOriginal = nullptr;

// -------------------- Logging --------------------
static void InitLog() {
    // Allocate a console window
    AllocConsole();

    // Redirect stdout to console
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);

    // Set console title
    SetConsoleTitleA("Language Hook - Debug Console");

    // Also open log file
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    strcat_s(path, "language_hook.log");
    fopen_s(&g_LogFile, path, "w");

    printf("[LOG] Console Initialized\n");
    if (g_LogFile) {
        fprintf(g_LogFile, "[LOG] Initialized\n");
        fflush(g_LogFile);
    }
}

static void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Log to console
    vprintf(fmt, args);

    // Log to file
    if (g_LogFile) {
        va_list args2;
        va_start(args2, fmt);
        vfprintf(g_LogFile, fmt, args2);
        va_end(args2);
        fflush(g_LogFile);
    }

    va_end(args);
}

static void CloseLog() {
    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
    FreeConsole();
}

// -------------------- Object Access --------------------
inline uint8_t GetEnabled(void* obj) {
    return *(uint8_t*)((uintptr_t)obj + 0xC0);
}

inline int32_t GetStoredCount(void* obj) {
    return *(int32_t*)((uintptr_t)obj + 0x108);
}

inline void SetStoredCount(void* obj, int32_t val) {
    *(int32_t*)((uintptr_t)obj + 0x108) = val;
}

inline int32_t GetSelectedIndex(void* obj) {
    return *(int32_t*)((uintptr_t)obj + 0x10C);
}

inline uint64_t* GetTableEntry(void* obj, int index) {
    return (uint64_t*)((uintptr_t)obj + 0x1370 + (index * 0x10));
}

// -------------------- Detour Function --------------------
void __fastcall Detour_TargetInit(void* param_1) {
    Log("[Detour] Called\n");

    // Call original
    if (g_fpOriginal) {
        g_fpOriginal(param_1);
    }
    else {
        Log("[Detour] ERROR: Original function pointer is NULL\n");
        return;
    }

    // Check if enabled
    if (!GetEnabled(param_1)) {
        Log("[Detour] Object not enabled, skipping\n");
        return;
    }

    int32_t count = GetStoredCount(param_1);
    int32_t numToAdd = (int32_t)g_LanguagesToAdd.size();

    Log("[Detour] After original call: stored_count=%d\n", count);
    Log("[Detour] Languages to add: %d\n", numToAdd);

    // Validate we have space for all entries
    if (count < 0 || count + numToAdd >= 256) {
        Log("[Detour] Invalid count or not enough space for %d entries, aborting\n", numToAdd);
        return;
    }

    // Dynamically append all language entries
    for (int i = 0; i < numToAdd; i++) {
        uint64_t* entry = GetTableEntry(param_1, count + i);
        entry[0] = g_LanguagesToAdd[i].key;
        entry[1] = g_LanguagesToAdd[i].value;

        Log("[Detour] Added [%d] %s: key=%llu, value=0x%012llX\n",
            i,
            g_LanguagesToAdd[i].name,
            g_LanguagesToAdd[i].key,
            g_LanguagesToAdd[i].value);
    }

    SetStoredCount(param_1, count + numToAdd);
    Log("[Detour] New stored_count=%d\n", count + numToAdd);

    // Debug: print all entries
    Log("[Detour] Table contents:\n");
    for (int i = 0; i < count + numToAdd; i++) {
        uint64_t* e = GetTableEntry(param_1, i);
        Log("  [%2d] key=%llu value=0x%012llX\n", i, e[0], e[1]);
    }
}

// -------------------- Hook Management --------------------
static bool InstallHook() {
    // Get module base
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) {
        Log("[Hook] Failed to get module handle\n");
        return false;
    }

    // Calculate target address
    g_TargetAddress = (void*)((uintptr_t)hModule + FUNCTION_OFFSET);
    Log("[Hook] Module base: 0x%p\n", hModule);
    Log("[Hook] Target address: 0x%p\n", g_TargetAddress);

    // Initialize MinHook
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        Log("[Hook] MH_Initialize failed: %d\n", status);
        return false;
    }

    // Create hook
    status = MH_CreateHook(
        g_TargetAddress,
        &Detour_TargetInit,
        reinterpret_cast<LPVOID*>(&g_fpOriginal)
    );

    if (status != MH_OK) {
        Log("[Hook] MH_CreateHook failed: %d\n", status);
        MH_Uninitialize();
        return false;
    }

    // Enable hook
    status = MH_EnableHook(g_TargetAddress);
    if (status != MH_OK) {
        Log("[Hook] MH_EnableHook failed: %d\n", status);
        MH_Uninitialize();
        return false;
    }

    Log("[Hook] Successfully installed at 0x%p\n", g_TargetAddress);
    Log("[Hook] Original function: 0x%p\n", g_fpOriginal);
    return true;
}

static void RemoveHook() {
    if (g_TargetAddress) {
        MH_DisableHook(g_TargetAddress);
        MH_RemoveHook(g_TargetAddress);
    }
    MH_Uninitialize();
    Log("[Hook] Removed\n");
}

// -------------------- Thread --------------------
static DWORD WINAPI InitThread(LPVOID) {
    InitLog();
    Log("[Init] Starting hook installation\n");
    Log("[Init] Configured to add %zu languages\n", g_LanguagesToAdd.size());

    // Print configured languages
    for (size_t i = 0; i < g_LanguagesToAdd.size(); i++) {
        Log("[Init]   - %s (key=%llu, value=0x%012llX)\n",
            g_LanguagesToAdd[i].name,
            g_LanguagesToAdd[i].key,
            g_LanguagesToAdd[i].value);
    }

    // Small delay to ensure process is fully loaded
    Sleep(1000);

    if (!InstallHook()) {
        Log("[Init] Hook installation failed\n");
        CloseLog();
        return 1;
    }

    Log("[Init] Hook installed successfully, waiting for function calls...\n");
    return 0;
}

// -------------------- DLL Entry Point --------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        RemoveHook();
        CloseLog();
        break;
    }
    return TRUE;
}